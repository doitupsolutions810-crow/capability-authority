import math

import pytest
import rfc8785

from plane_service.crypto_sign import canonical


@pytest.mark.parametrize(
    "value",
    [
        {"z": 1, "a": {"y": 2, "b": 3}},
        {"unicode": "München / 東京 / 🚀", "control": "\n\t"},
        {"small": 1e-7, "large": 1e21, "negative_zero": -0.0, "integer_float": 1.0},
        [None, True, False, 0, -1, 1.2345678901234567],
    ],
)
def test_signature_canonicalization_matches_rfc8785(value):
    assert canonical(value) == rfc8785.dumps(value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_signature_canonicalization_rejects_non_finite_numbers(value):
    with pytest.raises((ValueError, TypeError)):
        canonical({"unsafe": value})


def test_signature_canonicalization_is_not_python_json_dump_default():
    value = {"small": 1e-7, "integer_float": 1.0, "negative_zero": -0.0}
    assert canonical(value) == b'{"integer_float":1,"negative_zero":0,"small":1e-7}'
