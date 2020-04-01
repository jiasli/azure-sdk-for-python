# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from datetime import datetime
import time

from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError

from .. import AuthenticationRequiredError
from .._internal import ARM_SCOPE, PublicClientCredential, wrap_exceptions
from .._internal.msal_credentials import _build_auth_profile

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Optional, Tuple
    from azure.core.credentials import TokenCredential
    from .. import AuthProfile


class DeviceCodeCredential(PublicClientCredential):
    """Authenticates users through the device code flow.

    When :func:`get_token` is called, this credential acquires a verification URL and code from Azure Active Directory.
    A user must browse to the URL, enter the code, and authenticate with Azure Active Directory. If the user
    authenticates successfully, the credential receives an access token.

    For more information about the device code flow, see Azure Active Directory documentation:
    https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code

    :param str client_id: the application's ID

    :keyword str authority: Authority of an Azure Active Directory endpoint, for example 'login.microsoftonline.com',
          the authority for Azure Public Cloud (which is the default). :class:`~azure.identity.KnownAuthorities`
          defines authorities for other clouds.
    :keyword str tenant_id: an Azure Active Directory tenant ID. Defaults to the 'organizations' tenant, which can
          authenticate work or school accounts. **Required for single-tenant applications.**
    :keyword int timeout: seconds to wait for the user to authenticate. Defaults to the validity period of the
          device code as set by Azure Active Directory, which also prevails when ``timeout`` is longer.
    :keyword prompt_callback: A callback enabling control of how authentication
          instructions are presented. Must accept arguments (``verification_uri``, ``user_code``, ``expires_on``):

            - ``verification_uri`` (str) the URL the user must visit
            - ``user_code`` (str) the code the user must enter there
            - ``expires_on`` (datetime.datetime) the UTC time at which the code will expire
          If this argument isn't provided, the credential will print instructions to stdout.
    :paramtype prompt_callback: Callable[str, str, ~datetime.datetime]
    :keyword ~azure.identity.AuthProfile profile: a user profile from a prior authentication. If provided, keyword
          arguments ``authority`` and ``tenant_id`` will be ignored because the profile contains this information.
    :keyword bool silent_auth_only: authenticate only silently (without user interaction). False by default. If True,
          :func:`~get_token` will raise :class:`~azure.identity.AuthenticationRequiredError` when it cannot
          authenticate silently.
    """

    def __init__(self, client_id, **kwargs):
        # type: (str, **Any) -> None
        self._timeout = kwargs.pop("timeout", None)  # type: Optional[int]
        self._prompt_callback = kwargs.pop("prompt_callback", None)
        super(DeviceCodeCredential, self).__init__(client_id=client_id, **kwargs)

    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        # type: (*str, **Any) -> AccessToken
        """Request an access token for `scopes`.

        .. note:: This method is called by Azure SDK clients. It isn't intended for use in application code.

        :param str scopes: desired scopes for the access token. This method requires at least one scope.
        :rtype: :class:`azure.core.credentials.AccessToken`
        :raises ~azure.core.exceptions.ClientAuthenticationError: authentication failed. The error's ``message``
          attribute gives a reason. Any error response from Azure Active Directory is available as the error's
          ``response`` attribute.
        :raises ~azure.identity.AuthenticationRequiredError: the credential is configured to authenticate only silently
          (without user interaction), and was unable to do so.
        """
        if not scopes:
            raise ValueError("'get_token' requires at least one scope")

        token = self._acquire_token_silent(*scopes, **kwargs)
        if not token:
            if self._silent_auth_only:
                raise AuthenticationRequiredError()

            now = int(time.time())
            response = self._get_token_by_device_code(*scopes, **kwargs)

            # update profile because the user may have authenticated a different identity
            self._profile = _build_auth_profile(response)

            token = AccessToken(response["access_token"], now + int(response["expires_in"]))

        return token

    @classmethod
    def authenticate(cls, client_id, **kwargs):
        # type: (str, **Any) -> Tuple[DeviceCodeCredential, AuthProfile]
        """Authenticate a user. Returns a credential ready to get tokens for that user, and a user profile.

        Accepts the same keyword arguments as :class:`~DeviceCodeCredential`

        :param str client_id: Client ID of the Azure Active Directory application the user will sign in to
        :rtype: ~azure.identity.DeviceCodeCredential, ~azure.identity.AuthProfile
        :raises ~azure.core.exceptions.ClientAuthenticationError: authentication failed. The error's ``message``
          attribute gives a reason. Any error response from Azure Active Directory is available as the error's
          ``response`` attribute.
        """
        # pylint:disable=protected-access
        scope = kwargs.pop("scope", None) or ARM_SCOPE

        credential = cls(client_id, **kwargs)
        response = credential._get_token_by_device_code(scope)
        profile = _build_auth_profile(response)
        credential._profile = profile

        return credential, profile

    @wrap_exceptions
    def _get_token_by_device_code(self, *scopes):
        # MSAL requires scopes be a list
        scopes = list(scopes)  # type: ignore

        app = self._get_app()
        flow = app.initiate_device_flow(scopes)
        if "error" in flow:
            raise ClientAuthenticationError(
                message="Couldn't begin authentication: {}".format(flow.get("error_description") or flow.get("error"))
            )

        if self._prompt_callback:
            self._prompt_callback(
                flow["verification_uri"], flow["user_code"], datetime.utcfromtimestamp(flow["expires_at"])
            )
        else:
            print(flow["message"])

        if self._timeout is not None and self._timeout < flow["expires_in"]:
            # user specified an effective timeout we will observe
            deadline = int(time.time()) + self._timeout
            result = app.acquire_token_by_device_flow(flow, exit_condition=lambda flow: time.time() > deadline)
        else:
            # MSAL will stop polling when the device code expires
            result = app.acquire_token_by_device_flow(flow)

        if "access_token" not in result:
            if result.get("error") == "authorization_pending":
                message = "Timed out waiting for user to authenticate"
            else:
                message = "Authentication failed: {}".format(result.get("error_description") or result.get("error"))
            raise ClientAuthenticationError(message=message)

        return result


class UsernamePasswordCredential(PublicClientCredential):
    """Authenticates a user with a username and password.

    In general, Microsoft doesn't recommend this kind of authentication, because it's less secure than other
    authentication flows.

    Authentication with this credential is not interactive, so it is **not compatible with any form of
    multi-factor authentication or consent prompting**. The application must already have consent from the user or
    a directory admin.

    This credential can only authenticate work and school accounts; Microsoft accounts are not supported.
    See this document for more information about account types:
    https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/sign-up-organization

    :param str client_id: the application's client ID
    :param str username: the user's username (usually an email address)
    :param str password: the user's password

    :keyword str authority: Authority of an Azure Active Directory endpoint, for example 'login.microsoftonline.com',
          the authority for Azure Public Cloud (which is the default). :class:`~azure.identity.KnownAuthorities`
          defines authorities for other clouds.
    :keyword str tenant_id: tenant ID or a domain associated with a tenant. If not provided, defaults to the
          'organizations' tenant, which supports only Azure Active Directory work or school accounts.
    :keyword ~azure.identity.AuthProfile profile: a user profile from a prior authentication. If provided, keyword
          arguments ``authority`` and ``tenant_id`` will be ignored because the profile contains this information.
    :keyword bool silent_auth_only: authenticate only silently (without user interaction). False by default. If True,
          :func:`~get_token` will raise :class:`~azure.identity.AuthenticationRequiredError` when it cannot
          authenticate silently.
    """

    def __init__(self, client_id, username, password, **kwargs):
        # type: (str, str, str, Any) -> None
        super(UsernamePasswordCredential, self).__init__(client_id=client_id, **kwargs)
        self._username = username
        self._password = password

    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        # type: (*str, **Any) -> AccessToken
        """Request an access token for `scopes`.

        .. note:: This method is called by Azure SDK clients. It isn't intended for use in application code.

        :param str scopes: desired scopes for the access token. This method requires at least one scope.
        :rtype: :class:`azure.core.credentials.AccessToken`
        :raises ~azure.core.exceptions.ClientAuthenticationError: authentication failed. The error's ``message``
          attribute gives a reason. Any error response from Azure Active Directory is available as the error's
          ``response`` attribute.
        :raises ~azure.identity.AuthenticationRequiredError: the credential is configured to authenticate only silently
          (without user interaction), and was unable to do so.
        """
        if not scopes:
            raise ValueError("'get_token' requires at least one scope")

        token = self._acquire_token_silent(*scopes, **kwargs)
        if not token:
            if self._silent_auth_only:
                raise AuthenticationRequiredError()

            now = int(time.time())
            response = self._request_token(*scopes)

            # update profile because the user may have authenticated a different identity
            self._profile = _build_auth_profile(response)

            token = AccessToken(response["access_token"], now + int(response["expires_in"]))

        return token

    @wrap_exceptions
    def _request_token(self, *scopes):
        # MSAL requires scopes be a list
        scopes = list(scopes)  # type: ignore

        app = self._get_app()
        with self._adapter:
            result = app.acquire_token_by_username_password(
                username=self._username, password=self._password, scopes=scopes
            )

        if "access_token" not in result:
            raise ClientAuthenticationError(message="Authentication failed: {}".format(result.get("error_description")))

        return result

    @classmethod
    def authenticate(cls, client_id, username, password, **kwargs):
        # type: (str, str, str, **Any) -> Tuple[UsernamePasswordCredential, AuthProfile]
        """Authenticate a user. Returns a credential ready to get tokens for that user, and a user profile.

        Accepts the same keyword arguments as :class:`~UsernamePasswordCredential`

        :param str client_id: Client ID of the Azure Active Directory application the user will sign in to
        :param str username: the user's username (usually an email address)
        :param str password: the user's password
        :rtype: ~azure.identity.UsernamePasswordCredential, ~azure.identity.AuthProfile
        :raises ~azure.core.exceptions.ClientAuthenticationError: authentication failed. The error's ``message``
          attribute gives a reason. Any error response from Azure Active Directory is available as the error's
          ``response`` attribute.
        """
        # pylint:disable=protected-access
        scope = kwargs.pop("scope", None) or ARM_SCOPE

        credential = cls(client_id, username, password, **kwargs)

        response = credential._request_token(scope)
        profile = _build_auth_profile(response)
        credential._profile = profile

        return credential, profile
