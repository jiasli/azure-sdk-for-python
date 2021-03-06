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

from .. import models


class SpatialAnchorsAccountsOperations(object):
    """SpatialAnchorsAccountsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. Constant value: "2019-02-28-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-02-28-preview"

        self.config = config

    def list_by_subscription(
            self, custom_headers=None, raw=False, **operation_config):
        """List Spatial Anchors Accounts by Subscription.

        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of SpatialAnchorsAccount
        :rtype:
         ~azure.mgmt.mixedreality.models.SpatialAnchorsAccountPaged[~azure.mgmt.mixedreality.models.SpatialAnchorsAccount]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_subscription.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.SpatialAnchorsAccountPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.SpatialAnchorsAccountPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_subscription.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.MixedReality/spatialAnchorsAccounts'}

    def list_by_resource_group(
            self, resource_group_name, custom_headers=None, raw=False, **operation_config):
        """List Resources by Resource Group.

        :param resource_group_name: Name of an Azure resource group.
        :type resource_group_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of SpatialAnchorsAccount
        :rtype:
         ~azure.mgmt.mixedreality.models.SpatialAnchorsAccountPaged[~azure.mgmt.mixedreality.models.SpatialAnchorsAccount]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_resource_group.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.SpatialAnchorsAccountPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.SpatialAnchorsAccountPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/spatialAnchorsAccounts'}

    def delete(
            self, resource_group_name, spatial_anchors_account_name, custom_headers=None, raw=False, **operation_config):
        """Delete a Spatial Anchors Account.

        :param resource_group_name: Name of an Azure resource group.
        :type resource_group_name: str
        :param spatial_anchors_account_name: Name of an Mixed Reality Spatial
         Anchors Account.
        :type spatial_anchors_account_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'spatialAnchorsAccountName': self._serialize.url("spatial_anchors_account_name", spatial_anchors_account_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 204]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/spatialAnchorsAccounts/{spatialAnchorsAccountName}'}

    def get(
            self, resource_group_name, spatial_anchors_account_name, custom_headers=None, raw=False, **operation_config):
        """Retrieve a Spatial Anchors Account.

        :param resource_group_name: Name of an Azure resource group.
        :type resource_group_name: str
        :param spatial_anchors_account_name: Name of an Mixed Reality Spatial
         Anchors Account.
        :type spatial_anchors_account_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SpatialAnchorsAccount or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.mixedreality.models.SpatialAnchorsAccount or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'spatialAnchorsAccountName': self._serialize.url("spatial_anchors_account_name", spatial_anchors_account_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('SpatialAnchorsAccount', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/spatialAnchorsAccounts/{spatialAnchorsAccountName}'}

    def update(
            self, resource_group_name, spatial_anchors_account_name, location, tags=None, custom_headers=None, raw=False, **operation_config):
        """Updating a Spatial Anchors Account.

        :param resource_group_name: Name of an Azure resource group.
        :type resource_group_name: str
        :param spatial_anchors_account_name: Name of an Mixed Reality Spatial
         Anchors Account.
        :type spatial_anchors_account_name: str
        :param location: The geo-location where the resource lives
        :type location: str
        :param tags: Resource tags.
        :type tags: dict[str, str]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SpatialAnchorsAccount or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.mixedreality.models.SpatialAnchorsAccount or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        spatial_anchors_account = models.SpatialAnchorsAccount(tags=tags, location=location)

        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'spatialAnchorsAccountName': self._serialize.url("spatial_anchors_account_name", spatial_anchors_account_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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
        body_content = self._serialize.body(spatial_anchors_account, 'SpatialAnchorsAccount')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('SpatialAnchorsAccount', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/spatialAnchorsAccounts/{spatialAnchorsAccountName}'}

    def create(
            self, resource_group_name, spatial_anchors_account_name, location, tags=None, custom_headers=None, raw=False, **operation_config):
        """Creating or Updating a Spatial Anchors Account.

        :param resource_group_name: Name of an Azure resource group.
        :type resource_group_name: str
        :param spatial_anchors_account_name: Name of an Mixed Reality Spatial
         Anchors Account.
        :type spatial_anchors_account_name: str
        :param location: The geo-location where the resource lives
        :type location: str
        :param tags: Resource tags.
        :type tags: dict[str, str]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SpatialAnchorsAccount or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.mixedreality.models.SpatialAnchorsAccount or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        spatial_anchors_account = models.SpatialAnchorsAccount(tags=tags, location=location)

        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'spatialAnchorsAccountName': self._serialize.url("spatial_anchors_account_name", spatial_anchors_account_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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
        body_content = self._serialize.body(spatial_anchors_account, 'SpatialAnchorsAccount')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('SpatialAnchorsAccount', response)
        if response.status_code == 201:
            deserialized = self._deserialize('SpatialAnchorsAccount', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/spatialAnchorsAccounts/{spatialAnchorsAccountName}'}

    def get_keys(
            self, resource_group_name, spatial_anchors_account_name, custom_headers=None, raw=False, **operation_config):
        """Get Both of the 2 Keys of a Spatial Anchors Account.

        :param resource_group_name: Name of an Azure resource group.
        :type resource_group_name: str
        :param spatial_anchors_account_name: Name of an Mixed Reality Spatial
         Anchors Account.
        :type spatial_anchors_account_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SpatialAnchorsAccountKeys or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.mixedreality.models.SpatialAnchorsAccountKeys or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get_keys.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'spatialAnchorsAccountName': self._serialize.url("spatial_anchors_account_name", spatial_anchors_account_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('SpatialAnchorsAccountKeys', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_keys.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/spatialAnchorsAccounts/{spatialAnchorsAccountName}/keys'}

    def regenerate_keys(
            self, resource_group_name, spatial_anchors_account_name, serial=1, custom_headers=None, raw=False, **operation_config):
        """Regenerate 1 Key of a Spatial Anchors Account.

        :param resource_group_name: Name of an Azure resource group.
        :type resource_group_name: str
        :param spatial_anchors_account_name: Name of an Mixed Reality Spatial
         Anchors Account.
        :type spatial_anchors_account_name: str
        :param serial: serial of key to be regenerated
        :type serial: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SpatialAnchorsAccountKeys or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.mixedreality.models.SpatialAnchorsAccountKeys or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.mixedreality.models.ErrorResponseException>`
        """
        spatial_anchors_account_key_regenerate = models.SpatialAnchorsAccountKeyRegenerateRequest(serial=serial)

        # Construct URL
        url = self.regenerate_keys.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'spatialAnchorsAccountName': self._serialize.url("spatial_anchors_account_name", spatial_anchors_account_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

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
        body_content = self._serialize.body(spatial_anchors_account_key_regenerate, 'SpatialAnchorsAccountKeyRegenerateRequest')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('SpatialAnchorsAccountKeys', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    regenerate_keys.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/spatialAnchorsAccounts/{spatialAnchorsAccountName}/keys'}
