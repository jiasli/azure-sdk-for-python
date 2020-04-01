# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import socket
import time
import uuid
import webbrowser

from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError

from .. import AuthenticationRequiredError, CredentialUnavailableError
from .._constants import AZURE_CLI_CLIENT_ID
from .._internal import ARM_SCOPE, AuthCodeRedirectServer, PublicClientCredential, wrap_exceptions
from .._internal.msal_credentials import _build_auth_profile

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    # pylint:disable=unused-import
    from typing import Any, List, Mapping, Tuple
    from .. import AuthProfile


class InteractiveBrowserCredential(PublicClientCredential):
    """Opens a browser to interactively authenticate a user.

    :func:`~get_token` opens a browser to a login URL provided by Azure Active Directory and authenticates a user
    there with the authorization code flow. Azure Active Directory documentation describes this flow in more detail:
    https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code

    :keyword str authority: Authority of an Azure Active Directory endpoint, for example 'login.microsoftonline.com',
          the authority for Azure Public Cloud (which is the default). :class:`~azure.identity.KnownAuthorities`
          defines authorities for other clouds.
    :keyword str tenant_id: an Azure Active Directory tenant ID. Defaults to the 'organizations' tenant, which can
          authenticate work or school accounts.
    :keyword str client_id: Client ID of the Azure Active Directory application users will sign in to. If
          unspecified, the Azure CLI's ID will be used.
    :keyword ~azure.identity.AuthProfile profile: a user profile from a prior authentication. If provided, keyword
          arguments ``authority`` and ``tenant_id`` will be ignored because the profile contains this information.
    :keyword bool silent_auth_only: authenticate only silently (without user interaction). False by default. If True,
          :func:`~get_token` will raise :class:`~azure.identity.AuthenticationRequiredError` when it cannot
          authenticate silently.
    :keyword int timeout: seconds to wait for the user to complete authentication. Defaults to 300 (5 minutes).
    """

    def __init__(self, **kwargs):
        # type: (**Any) -> None
        self._timeout = kwargs.pop("timeout", 300)
        self._server_class = kwargs.pop("server_class", AuthCodeRedirectServer)  # facilitate mocking
        client_id = kwargs.pop("client_id", AZURE_CLI_CLIENT_ID)
        super(InteractiveBrowserCredential, self).__init__(client_id=client_id, **kwargs)

    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        # type: (*str, **Any) -> AccessToken
        """Request an access token for `scopes`.

        This will open a browser to a login page and listen on localhost for a request indicating authentication has
        completed.

        .. note:: This method is called by Azure SDK clients. It isn't intended for use in application code.

        :param str scopes: desired scopes for the access token. This method requires at least one scope.
        :rtype: :class:`azure.core.credentials.AccessToken`
        :raises ~azure.identity.CredentialUnavailableError: the credential is unable to start an HTTP server on
          localhost, or is unable to open a browser
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
            response = self._get_token_by_auth_code(*scopes, **kwargs)

            # update profile because the user may have authenticated a different identity
            self._profile = _build_auth_profile(response)

            token = AccessToken(response["access_token"], now + int(response["expires_in"]))

        return token

    @classmethod
    def authenticate(cls, client_id, **kwargs):
        # type: (str, **Any) -> Tuple[InteractiveBrowserCredential, AuthProfile]
        """Authenticate a user. Returns a credential ready to get tokens for that user, and a user profile.

        This method will open a browser to a login page and listen on localhost for a request indicating authentication
        has completed.

        Accepts the same keyword arguments as :class:`~InteractiveBrowserCredential`

        :param str client_id: Client ID of the Azure Active Directory application the user will sign in to
        :rtype: ~azure.identity.InteractiveBrowserCredential, ~azure.identity.AuthProfile
        :raises ~azure.identity.CredentialUnavailableError: the credential is unable to start an HTTP server on
          localhost, or is unable to open a browser
        :raises ~azure.core.exceptions.ClientAuthenticationError: authentication failed. The error's ``message``
          attribute gives a reason. Any error response from Azure Active Directory is available as the error's
          ``response`` attribute.
        """
        # pylint:disable=protected-access
        scope = kwargs.pop("scope", None) or ARM_SCOPE

        credential = cls(client_id=client_id, **kwargs)
        response = credential._get_token_by_auth_code(scope)
        profile = _build_auth_profile(response)
        credential._profile = profile

        return credential, profile

    @wrap_exceptions
    def _get_token_by_auth_code(self, *scopes, **kwargs):
        # start an HTTP server on localhost to receive the redirect
        for port in range(8400, 9000):
            try:
                server = self._server_class(port, timeout=self._timeout)
                redirect_uri = "http://localhost:{}".format(port)
                break
            except socket.error:
                continue  # keep looking for an open port

        if not redirect_uri:
            raise CredentialUnavailableError(message="Couldn't start an HTTP server on localhost")

        # get the url the user must visit to authenticate
        scopes = list(scopes)  # type: ignore
        request_state = str(uuid.uuid4())
        app = self._get_app()
        auth_url = app.get_authorization_request_url(
            scopes, redirect_uri=redirect_uri, state=request_state, prompt="select_account", **kwargs
        )

        # open browser to that url
        if not webbrowser.open(auth_url):
            raise CredentialUnavailableError(message="Failed to open a browser")

        # block until the server times out or receives the post-authentication redirect
        response = server.wait_for_redirect()
        if not response:
            raise ClientAuthenticationError(
                message="Timed out after waiting {} seconds for the user to authenticate".format(self._timeout)
            )

        # redeem the authorization code for a token
        code = self._parse_response(request_state, response)
        result = app.acquire_token_by_authorization_code(code, scopes=scopes, redirect_uri=redirect_uri, **kwargs)

        if "access_token" not in result:
            raise ClientAuthenticationError(message="Authentication failed: {}".format(result.get("error_description")))

        return result

    @staticmethod
    def _parse_response(request_state, response):
        # type: (str, Mapping[str, Any]) -> List[str]
        """Validates ``response`` and returns the authorization code it contains, if authentication succeeded.

        Raises :class:`azure.core.exceptions.ClientAuthenticationError`, if authentication failed or ``response`` is
        malformed.
        """

        if "error" in response:
            message = "Authentication failed: {}".format(response.get("error_description") or response["error"])
            raise ClientAuthenticationError(message=message)
        if "code" not in response:
            # a response with no error or code is malformed; we don't know what to do with it
            message = "Authentication server didn't send an authorization code"
            raise ClientAuthenticationError(message=message)

        # response must include the state sent in the auth request
        if "state" not in response:
            raise ClientAuthenticationError(message="Authentication response doesn't include OAuth state")
        if response["state"][0] != request_state:
            raise ClientAuthenticationError(message="Authentication response's OAuth state doesn't match the request's")

        return response["code"]
