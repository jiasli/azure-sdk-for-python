# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

import uuid
from msrest.pipeline import ClientRawResponse
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling

from .. import models


class SubscriptionFactoryOperations(object):
    """SubscriptionFactoryOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config


    def _create_subscription_initial(
            self, billing_account_name, invoice_section_name, body, custom_headers=None, raw=False, **operation_config):
        api_version = "2018-11-01-preview"

        # Construct URL
        url = self.create_subscription.metadata['url']
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'invoiceSectionName': self._serialize.url("invoice_section_name", invoice_section_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(body, 'ModernSubscriptionCreationParameters')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        header_dict = {}

        if response.status_code == 200:
            deserialized = self._deserialize('SubscriptionCreationResult', response)
            header_dict = {
                'Location': 'str',
                'Retry-After': 'int',
            }

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            client_raw_response.add_headers(header_dict)
            return client_raw_response

        return deserialized

    def create_subscription(
            self, billing_account_name, invoice_section_name, body, custom_headers=None, raw=False, polling=True, **operation_config):
        """The operation to create a new Azure subscription.

        :param billing_account_name: The name of the Microsoft Customer
         Agreement billing account for which you want to create the
         subscription.
        :type billing_account_name: str
        :param invoice_section_name: The name of the invoice section in the
         billing account for which you want to create the subscription.
        :type invoice_section_name: str
        :param body: The subscription creation parameters.
        :type body:
         ~azure.mgmt.subscription.models.ModernSubscriptionCreationParameters
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns
         SubscriptionCreationResult or
         ClientRawResponse<SubscriptionCreationResult> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.subscription.models.SubscriptionCreationResult]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.subscription.models.SubscriptionCreationResult]]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.subscription.models.ErrorResponseException>`
        """
        raw_result = self._create_subscription_initial(
            billing_account_name=billing_account_name,
            invoice_section_name=invoice_section_name,
            body=body,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            header_dict = {
                'Location': 'str',
                'Retry-After': 'int',
            }
            deserialized = self._deserialize('SubscriptionCreationResult', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                client_raw_response.add_headers(header_dict)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    create_subscription.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/invoiceSections/{invoiceSectionName}/providers/Microsoft.Subscription/createSubscription'}


    def _create_subscription_in_enrollment_account_initial(
            self, enrollment_account_name, body, custom_headers=None, raw=False, **operation_config):
        api_version = "2018-03-01-preview"

        # Construct URL
        url = self.create_subscription_in_enrollment_account.metadata['url']
        path_format_arguments = {
            'enrollmentAccountName': self._serialize.url("enrollment_account_name", enrollment_account_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(body, 'SubscriptionCreationParameters')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        header_dict = {}

        if response.status_code == 200:
            deserialized = self._deserialize('SubscriptionCreationResult', response)
            header_dict = {
                'Location': 'str',
                'Retry-After': 'str',
            }

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            client_raw_response.add_headers(header_dict)
            return client_raw_response

        return deserialized

    def create_subscription_in_enrollment_account(
            self, enrollment_account_name, body, custom_headers=None, raw=False, polling=True, **operation_config):
        """Creates an Azure subscription.

        :param enrollment_account_name: The name of the enrollment account to
         which the subscription will be billed.
        :type enrollment_account_name: str
        :param body: The subscription creation parameters.
        :type body:
         ~azure.mgmt.subscription.models.SubscriptionCreationParameters
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns
         SubscriptionCreationResult or
         ClientRawResponse<SubscriptionCreationResult> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.subscription.models.SubscriptionCreationResult]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.subscription.models.SubscriptionCreationResult]]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.subscription.models.ErrorResponseException>`
        """
        raw_result = self._create_subscription_in_enrollment_account_initial(
            enrollment_account_name=enrollment_account_name,
            body=body,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            header_dict = {
                'Location': 'str',
                'Retry-After': 'str',
            }
            deserialized = self._deserialize('SubscriptionCreationResult', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                client_raw_response.add_headers(header_dict)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    create_subscription_in_enrollment_account.metadata = {'url': '/providers/Microsoft.Billing/enrollmentAccounts/{enrollmentAccountName}/providers/Microsoft.Subscription/createSubscription'}
