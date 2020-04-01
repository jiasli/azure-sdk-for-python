# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json

from azure.identity import AuthProfile


def test_serialize_additional_data():
    """serialize should accept arbitrary additional key/value pairs, which deserialize should ignore"""

    attrs = ("environment", "home_account_id", "tenant_id", "username")
    nums = (n for n in range(len(attrs)))
    profile_values = {attr: next(nums) for attr in attrs}
    additional_data = {"foo": "bar", "bar": "quux"}

    profile = AuthProfile(**profile_values)
    serialized = profile.serialize(**additional_data)

    # AuthProfile's fields and the additional data should have been serialized
    assert json.loads(serialized) == dict(profile_values, **additional_data)

    deserialized = AuthProfile.deserialize(serialized)

    # the deserialized profile and the constructed profile should have the same fields
    assert sorted(vars(deserialized)) == sorted(vars(profile))

    # the constructed and deserialized profiles should have the same values
    assert all(getattr(deserialized, attr) == profile_values[attr] for attr in attrs)

    # deserialized profile should expose additional data like a dictionary
    assert all(deserialized[key] == additional_data[key] for key in additional_data)
