# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from azure.core.pipeline.policies import ContentDecodePolicy, SansIOHTTPPolicy
from azure.identity import AuthenticationRequiredError, UsernamePasswordCredential
from azure.identity._internal.user_agent import USER_AGENT
from msal import TokenCache
import pytest

from helpers import (
    build_aad_response,
    build_id_token,
    get_discovery_response,
    mock_response,
    Request,
    validating_transport,
)

try:
    from unittest.mock import Mock
except ImportError:  # python < 3.3
    from mock import Mock  # type: ignore


def test_no_scopes():
    """The credential should raise when get_token is called with no scopes"""

    credential = UsernamePasswordCredential("client-id", "username", "password")
    with pytest.raises(ValueError):
        credential.get_token()


def test_authenticate():
    """authenticate should return a ready-to-use credential instance and an AuthProfile for the authenticated user"""

    client_id = "client-id"
    environment = "localhost"
    issuer = "https://" + environment
    tenant_id = "some-tenant"
    authority = issuer + "/" + tenant_id

    access_token = "***"
    scope = "scope"

    # mock AAD response with id token
    object_id = "object-id"
    home_tenant = "home-tenant-id"
    username = "me@work.com"
    id_token = build_id_token(aud=client_id, iss=issuer, object_id=object_id, tenant_id=home_tenant, username=username)
    auth_response = build_aad_response(
        uid=object_id, utid=home_tenant, access_token=access_token, refresh_token="**", id_token=id_token
    )

    transport = validating_transport(
        requests=[Request(url_substring=issuer)] * 4,
        responses=[get_discovery_response(authority)] * 2
        + [mock_response(json_payload={}), mock_response(json_payload=auth_response)],
    )

    credential, profile = UsernamePasswordCredential.authenticate(
        client_id,
        username=username,
        password="supersecret",
        transport=transport,
        scope=scope,
        authority=environment,
        tenant_id=tenant_id,
        _cache=TokenCache(),
    )

    assert isinstance(credential, UsernamePasswordCredential)

    # credential should have a cached access token for the scope used in authenticate
    token = credential.get_token(scope)
    assert token.token == access_token

    assert profile.environment == environment
    assert profile.home_account_id == object_id + "." + home_tenant
    assert profile.tenant_id == home_tenant
    assert profile.username == username


def test_silent_auth_only():
    """When configured for strict silent auth, the credential should raise when silent auth fails"""

    empty_cache = TokenCache()  # empty cache makes silent auth impossible
    transport = Mock(send=Mock(side_effect=Exception("no request should be sent")))
    credential = UsernamePasswordCredential(
        "client-id", "username", "password", silent_auth_only=True, transport=transport, _cache=empty_cache
    )

    with pytest.raises(AuthenticationRequiredError):
        credential.get_token("scope")


def test_policies_configurable():
    policy = Mock(spec_set=SansIOHTTPPolicy, on_request=Mock())

    transport = validating_transport(
        requests=[Request()] * 3,
        responses=[get_discovery_response()] * 2 + [mock_response(json_payload=build_aad_response(access_token="**"))],
    )
    credential = UsernamePasswordCredential(
        "client-id", "username", "password", policies=[policy], transport=transport, _cache=TokenCache()
    )

    credential.get_token("scope")

    assert policy.on_request.called


def test_user_agent():
    transport = validating_transport(
        requests=[Request()] * 2 + [Request(required_headers={"User-Agent": USER_AGENT})],
        responses=[get_discovery_response()] * 2 + [mock_response(json_payload=build_aad_response(access_token="**"))],
    )

    credential = UsernamePasswordCredential(
        "client-id", "username", "password", transport=transport, _cache=TokenCache()
    )

    credential.get_token("scope")


def test_username_password_credential():
    expected_token = "access-token"
    transport = validating_transport(
        requests=[Request()] * 3,  # not validating requests because they're formed by MSAL
        responses=[
            # tenant discovery
            mock_response(json_payload={"authorization_endpoint": "https://a/b", "token_endpoint": "https://a/b"}),
            # user realm discovery, interests MSAL only when the response body contains account_type == "Federated"
            mock_response(json_payload={}),
            # token request
            mock_response(
                json_payload={
                    "access_token": expected_token,
                    "expires_in": 42,
                    "token_type": "Bearer",
                    "ext_expires_in": 42,
                }
            ),
        ],
    )

    credential = UsernamePasswordCredential(
        client_id="some-guid",
        username="user@azure",
        password="secret_password",
        transport=transport,
        instance_discovery=False,  # kwargs are passed to MSAL; this one prevents an AAD verification request
        _cache=TokenCache(),
    )

    token = credential.get_token("scope")
    assert token.token == expected_token
