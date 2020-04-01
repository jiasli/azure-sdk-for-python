# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class AuthProfile(object):
    """Public user information from an authentication.

    :param str environment: the Azure Active Directory instance which authenticated the user
    :param str home_account_id: the user's Azure Active Directory object ID and home tenant ID
    :param str tenant_id: the tenant which authenticated the user
    :param str username: the user's username (usually an email address)
    """

    def __init__(self, environment, home_account_id, tenant_id, username, **kwargs):
        # type: (str, str, str, str, **Any) -> None
        self._additional_data = kwargs
        self.environment = environment
        self.home_account_id = home_account_id
        self.tenant_id = tenant_id
        self.username = username

    @property
    def additional_data(self):
        # type: () -> dict
        """A dictionary of extra data deserialized alongside the profile"""

        return dict(self._additional_data)

    def __getitem__(self, key):
        return getattr(self, key, None) or self._additional_data[key]

    @classmethod
    def deserialize(cls, json_string):
        # type: (str) -> AuthProfile
        """Deserialize a profile from JSON"""

        deserialized = json.loads(json_string)

        return cls(
            environment=deserialized.pop("environment"),
            home_account_id=deserialized.pop("home_account_id"),
            tenant_id=deserialized.pop("tenant_id"),
            username=deserialized.pop("username"),
            **deserialized
        )

    def serialize(self, **kwargs):
        # type: (**Any) -> str
        """Serialize the profile and any keyword arguments to JSON"""

        profile = dict(
            {
                "environment": self.environment,
                "home_account_id": self.home_account_id,
                "tenant_id": self.tenant_id,
                "username": self.username,
            },
            **kwargs
        )

        return json.dumps(profile)
