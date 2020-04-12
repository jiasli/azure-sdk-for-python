# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
"""Credentials wrapping MSAL applications and delegating token acquisition and caching to them.
This entails monkeypatching MSAL's OAuth client with an adapter substituting an azure-core pipeline for Requests.
"""
import abc
import json
import logging
import os
import sys
import time

import msal
from six.moves.urllib_parse import urlparse
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError

from .exception_wrapper import wrap_exceptions
from .msal_transport_adapter import MsalTransportAdapter
from .._internal import get_default_authority
from .._auth_profile import AuthProfile

try:
    ABC = abc.ABC
except AttributeError:  # Python 2.7, abc exists, but not ABC
    ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})  # type: ignore

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    # pylint:disable=ungrouped-imports,unused-import
    from typing import Any, Mapping, Optional, Tuple, Type, Union
    from azure.core.credentials import TokenCredential


_LOGGER = logging.getLogger(__name__)


def _build_auth_profile(response):
    """Build an AuthProfile from the result of an MSAL ClientApplication token request"""

    try:
        client_info = json.loads(msal.oauth2cli.oidc.decode_part(response["client_info"]))
        id_token = response["id_token_claims"]

        return AuthProfile(
            environment=urlparse(id_token["iss"]).netloc,  # "iss" is the URL of the issuing tenant
            home_account_id="{uid}.{utid}".format(**client_info),
            tenant_id=id_token["tid"],  # tenant which issued the token, not necessarily user's home tenant
            username=id_token["preferred_username"],
        )
    except (KeyError, ValueError):
        # ClientApplication always requests client_info and id token, whose shapes shouldn't change; this is surprising
        return None


def _account_matches_profile(account, profile):
    return (
        account.get("home_account_id") == profile.home_account_id and account.get("environment") == profile.environment
    )


def _load_cache():
    # type: () -> msal.TokenCache

    if sys.platform.startswith("win") and "LOCALAPPDATA" in os.environ:
        from msal_extensions.token_cache import WindowsTokenCache

        return WindowsTokenCache(
            cache_location=os.path.join(os.environ["LOCALAPPDATA"], ".IdentityService", "msal.cache")
        )

    _LOGGER.warning("Using an in-memory cache because persistent caching isn't supported on this platform.")
    return msal.TokenCache()


class MsalCredential(ABC):
    """Base class for credentials wrapping MSAL applications"""

    def __init__(self, client_id, client_credential=None, **kwargs):
        # type: (str, Optional[Union[str, Mapping[str, str]]], **Any) -> None
        self._profile = kwargs.pop("profile", None)  # type: Optional[AuthProfile]
        if self._profile:
            authority = self._profile.environment
            tenant_id = self._profile.tenant_id
        else:
            authority = kwargs.pop("authority", None) or get_default_authority()
            tenant_id = kwargs.pop("tenant_id", None) or "organizations"

        self._base_url = "https://" + "/".join((authority.strip("/"), tenant_id.strip("/")))
        self._client_credential = client_credential
        self._client_id = client_id
        self._cache = kwargs.pop("_cache", None) or _load_cache()
        self._silent_auth_only = kwargs.pop("silent_auth_only", False)
        self._adapter = kwargs.pop("msal_adapter", None) or MsalTransportAdapter(**kwargs)

        # postpone creating the wrapped application because its initializer uses the network
        self._msal_app = None  # type: Optional[msal.ClientApplication]

    @abc.abstractmethod
    def get_token(self, *scopes, **kwargs):
        # type: (*str, **Any) -> AccessToken
        pass

    @abc.abstractmethod
    def _get_app(self):
        # type: () -> msal.ClientApplication
        pass

    def _create_app(self, cls, **kwargs):
        # type: (Type[msal.ClientApplication], **Any) -> msal.ClientApplication
        """Creates an MSAL application, patching msal.authority to use an azure-core pipeline during tenant discovery"""

        # MSAL application initializers use msal.authority to send AAD tenant discovery requests
        with self._adapter:
            # MSAL's "authority" is a URL e.g. https://login.microsoftonline.com/common
            app = cls(
                client_id=self._client_id,
                client_credential=self._client_credential,
                authority=self._base_url,
                token_cache=self._cache,
                **kwargs
            )

        # monkeypatch the app to replace requests.Session with MsalTransportAdapter
        app.client.session.close()
        app.client.session = self._adapter

        return app

    @wrap_exceptions
    def _acquire_token_silent(self, *scopes, **kwargs):
        if self._profile:
            app = self._get_app()
            for account in app.get_accounts(username=self._profile.username):
                if not _account_matches_profile(account, self._profile):
                    continue

                now = int(time.time())
                token = app.acquire_token_silent(list(scopes), account=account, **kwargs)
                try:
                    return AccessToken(token["access_token"], now + int(token["expires_in"]))
                except (TypeError, KeyError):
                    # 'token' has an unexpected type or shape, which is surprising
                    continue
        return None


class ConfidentialClientCredential(MsalCredential):
    """Wraps an MSAL ConfidentialClientApplication with the TokenCredential API"""

    @wrap_exceptions
    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        # type: (*str, **Any) -> AccessToken

        # MSAL requires scopes be a list
        scopes = list(scopes)  # type: ignore
        now = int(time.time())

        # First try to get a cached access token or if a refresh token is cached, redeem it for an access token.
        # Failing that, acquire a new token.
        app = self._get_app()
        result = app.acquire_token_silent(scopes, account=None) or app.acquire_token_for_client(scopes)

        if "access_token" not in result:
            raise ClientAuthenticationError(message="authentication failed: {}".format(result.get("error_description")))

        return AccessToken(result["access_token"], now + int(result["expires_in"]))

    def _get_app(self):
        # type: () -> msal.ConfidentialClientApplication
        if not self._msal_app:
            self._msal_app = self._create_app(msal.ConfidentialClientApplication)
        return self._msal_app


class PublicClientCredential(MsalCredential):
    """Wraps an MSAL PublicClientApplication with the TokenCredential API"""

    @abc.abstractmethod
    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        # type: (*str, **Any) -> AccessToken
        pass

    def _get_app(self):
        # type: () -> msal.PublicClientApplication
        if not self._msal_app:
            self._msal_app = self._create_app(msal.PublicClientApplication)
        return self._msal_app
