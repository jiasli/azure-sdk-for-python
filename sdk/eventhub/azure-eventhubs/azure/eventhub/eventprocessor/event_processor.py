# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# -----------------------------------------------------------------------------------

from typing import Callable, List
import uuid
import asyncio
import logging

from azure.eventhub import EventPosition, EventHubError
from azure.eventhub.aio import EventHubClient
from .checkpoint_manager import CheckpointManager
from .partition_manager import PartitionManager
from .partition_processor import PartitionProcessor, CloseReason
from .utils import get_running_loop

log = logging.getLogger(__name__)


class EventProcessor(object):
    def __init__(self, eventhub_client: EventHubClient, consumer_group_name: str,
                 partition_processor_factory: Callable[..., PartitionProcessor],
                 partition_manager: PartitionManager, **kwargs):
        """An EventProcessor automatically creates and runs consumers for all partitions of the eventhub.

        It provides the user a convenient way to receive events from multiple partitions and save checkpoints.
        If multiple EventProcessors are running for an event hub, they will automatically balance loading. This feature
        won't be availabe until preview 3.

        :param consumer_group_name: the consumer group that is used to receive events
        from the event hub that the eventhub_client is going to receive events from
        :param eventhub_client: an instance of azure.eventhub.aio.EventClient object
        :param partition_processor_callable: a callable that is called to return a PartitionProcessor
        :param partition_manager: an instance of a PartitionManager implementation
        :param initial_event_position: the offset to start a partition consumer if the partition has no checkpoint yet
        """
        self._consumer_group_name = consumer_group_name
        self._eventhub_client = eventhub_client
        self._eventhub_name = eventhub_client.eh_name
        self._partition_processor_factory = partition_processor_factory
        self._partition_manager = partition_manager
        self._initial_event_position = kwargs.get("initial_event_position", "-1")
        self._max_batch_size = eventhub_client.config.max_batch_size
        self._receive_timeout = eventhub_client.config.receive_timeout
        self._tasks: List[asyncio.Task] = []
        self._instance_id = str(uuid.uuid4())
        self._partition_ids = None

    async def start(self):
        """Start the EventProcessor.
            1. retrieve the partition ids from eventhubs
            2. claim partition ownership of these partitions.
            3. repeatedly call EvenHubConsumer.receive() to retrieve events and
            call user defined PartitionProcessor.process_events()
        """
        log.info("EventProcessor %r is being started", self._instance_id)
        partition_ids = await self._eventhub_client.get_partition_ids()
        self.partition_ids = partition_ids
        claimed_list = await self._claim_partitions()
        await self._start_claimed_partitions(claimed_list)

    async def stop(self):
        """Stop all the partition consumer

        It sends out a cancellation token to stop all partitions' EventHubConsumer will stop receiving events.

        """
        for task in self._tasks:
            task.cancel()
            # It's not agreed whether a partition manager has method close().
        log.info("EventProcessor %r has been cancelled", self._instance_id)

    async def _claim_partitions(self):
        partitions_ownership = await self._partition_manager.list_ownership(self._eventhub_name, self._consumer_group_name)
        partitions_ownership_dict = dict()
        for ownership in partitions_ownership:
            partitions_ownership_dict[ownership["partition_id"]] = ownership

        to_claim_list = []
        for pid in self.partition_ids:
            p_ownership = partitions_ownership_dict.get(pid)
            if p_ownership:
                to_claim_list.append(p_ownership)
            else:
                new_ownership = dict()
                new_ownership["eventhub_name"] = self._eventhub_name
                new_ownership["consumer_group_name"] = self._consumer_group_name
                new_ownership["instance_id"] = self._instance_id
                new_ownership["partition_id"] = pid
                new_ownership["owner_level"] = 1  # will increment in preview 3
                to_claim_list.append(new_ownership)
        claimed_list = await self._partition_manager.claim_ownership(to_claim_list)
        return claimed_list

    async def _start_claimed_partitions(self, claimed_partitions):
        consumers = []
        for partition in claimed_partitions:
            partition_id = partition["partition_id"]
            offset = partition.get("offset")
            offset = offset or self._initial_event_position
            consumer = self._eventhub_client.create_consumer(self._consumer_group_name, partition_id,
                                                            EventPosition(str(offset)))
            consumers.append(consumer)

            partition_processor = self._partition_processor_factory(
                eventhub_name=self._eventhub_name,
                consumer_group_name=self._consumer_group_name,
                partition_id=partition_id,
                checkpoint_manager=CheckpointManager(partition_id, self._eventhub_name, self._consumer_group_name,
                                                     self._instance_id, self._partition_manager)
            )
            loop = get_running_loop()
            task = loop.create_task(
                _receive(consumer, partition_processor, self._receive_timeout))
            self._tasks.append(task)

        await asyncio.gather(*self._tasks)
        await self._partition_manager.close()
        log.info("EventProcessor %r partition manager is closed", self._instance_id)
        log.info("EventProcessor %r has stopped", self._instance_id)


async def _receive(partition_consumer, partition_processor, receive_timeout):
    try:
        while True:
            try:
                events = await partition_consumer.receive(timeout=receive_timeout)
            except asyncio.CancelledError:
                await partition_processor.close(reason=CloseReason.SHUTDOWN)
                log.info(
                    "PartitionProcessor of EventProcessor instance %r of eventhub %r partition %r consumer group %r "
                    "has been shutdown",
                    partition_processor._checkpoint_manager._instance_id,
                    partition_processor._eventhub_name,
                    partition_processor._partition_id,
                    partition_processor._consumer_group_name
                )
                break
            except EventHubError as eh_err:
                reason = CloseReason.LEASE_LOST if eh_err.error == "link:stolen" else CloseReason.EVENTHUB_EXCEPTION
                log.info(
                    "PartitionProcessor of EventProcessor instance %r of eventhub %r partition %r consumer group %r "
                    "has met an exception receiving events. It's being closed. The exception is %r.",
                    partition_processor._checkpoint_manager._instance_id,
                    partition_processor._eventhub_name,
                    partition_processor._partition_id,
                    partition_processor._consumer_group_name,
                    eh_err
                )
                await partition_processor.process_error(eh_err)
                await partition_processor.close(reason=reason)
                break
            try:
                await partition_processor.process_events(events)
            except Exception as exp:  # user code has caused an error
                log.info(
                    "PartitionProcessor of EventProcessor instance %r of eventhub %r partition %r consumer group %r "
                    "has met an exception from user code process_events. It's being closed. The exception is %r.",
                    partition_processor._checkpoint_manager._instance_id,
                    partition_processor._eventhub_name,
                    partition_processor._partition_id,
                    partition_processor._consumer_group_name,
                    exp
                )
                await partition_processor.process_error(exp)
                # TODO: will review whether to break and close partition processor after user's code has an exception
        # TODO: try to inform other EventProcessors to take the partition when this partition is closed in preview 3?
    finally:
        await partition_consumer.close()