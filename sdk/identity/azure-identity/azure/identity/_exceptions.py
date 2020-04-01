# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from azure.core.exceptions import ClientAuthenticationError


class CredentialUnavailableError(ClientAuthenticationError):
    """The credential did not attempt to authenticate because required data or state is unavailable."""


class AuthenticationRequiredError(CredentialUnavailableError):
    """The credential was unable to authenticate silently."""
