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

from msrest.serialization import Model


class TimeSeriesCreateRequest(Model):
    """TimeSeriesCreateRequest.

    All required parameters must be populated in order to send to Azure.

    :param granularity: Required. Can only be one of yearly, monthly, weekly,
     daily, hourly or minutely. Granularity is used for verify whether input
     series is valid. Possible values include: 'yearly', 'monthly', 'weekly',
     'daily', 'hourly', 'minutely'
    :type granularity: str or
     ~azure.cognitiveservices.anomalydetector.models.Granularity
    :param custom_interval: Custom Interval is used to set non-standard time
     interval, for example, if the series is 5 minutes, request can be set as
     {"granularity":"minutely", "customInterval":5}.
    :type custom_interval: int
    :param retention_duration_in_hours: Hours that the data is kept.
    :type retention_duration_in_hours: int
    """

    _validation = {
        'granularity': {'required': True},
    }

    _attribute_map = {
        'granularity': {'key': 'granularity', 'type': 'Granularity'},
        'custom_interval': {'key': 'customInterval', 'type': 'int'},
        'retention_duration_in_hours': {'key': 'retentionDurationInHours', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(TimeSeriesCreateRequest, self).__init__(**kwargs)
        self.granularity = kwargs.get('granularity', None)
        self.custom_interval = kwargs.get('custom_interval', None)
        self.retention_duration_in_hours = kwargs.get('retention_duration_in_hours', None)
