# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
"""Credentials for Azure SDK clients."""

from ._auth_profile import AuthProfile
from ._exceptions import AuthenticationRequiredError, CredentialUnavailableError
from ._constants import KnownAuthorities
from ._credentials import (
    AuthorizationCodeCredential,
    CertificateCredential,
    ChainedTokenCredential,
    ClientSecretCredential,
    DefaultAzureCredential,
    DeviceCodeCredential,
    EnvironmentCredential,
    InteractiveBrowserCredential,
    ManagedIdentityCredential,
    SharedTokenCacheCredential,
    UsernamePasswordCredential,
)


__all__ = [
    "AuthenticationRequiredError",
    "AuthProfile",
    "AuthorizationCodeCredential",
    "CertificateCredential",
    "ChainedTokenCredential",
    "ClientSecretCredential",
    "CredentialUnavailableError",
    "DefaultAzureCredential",
    "DeviceCodeCredential",
    "EnvironmentCredential",
    "InteractiveBrowserCredential",
    "KnownAuthorities",
    "ManagedIdentityCredential",
    "SharedTokenCacheCredential",
    "UsernamePasswordCredential",
]

from ._version import VERSION

__version__ = VERSION
