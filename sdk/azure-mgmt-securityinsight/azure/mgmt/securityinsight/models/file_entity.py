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

from .entity import Entity


class FileEntity(Entity):
    """Represents a file entity.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar type: Azure resource type
    :vartype type: str
    :ivar name: Azure resource name
    :vartype name: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :ivar directory: The full path to the file.
    :vartype directory: str
    :ivar file_name: The file name without path (some alerts might not include
     path).
    :vartype file_name: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'kind': {'required': True},
        'directory': {'readonly': True},
        'file_name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'directory': {'key': 'properties.directory', 'type': 'str'},
        'file_name': {'key': 'properties.fileName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(FileEntity, self).__init__(**kwargs)
        self.directory = None
        self.file_name = None
        self.kind = 'File'