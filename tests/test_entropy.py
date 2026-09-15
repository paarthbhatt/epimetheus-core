"""Shannon entropy unit tests."""

from __future__ import annotations

import math
import random
import string

from epimetheus_core.entropy import shannon_entropy


def test_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_uniform_single_char_is_zero():
    assert shannon_entropy("aaaaaa") == 0.0


def test_two_symbols_is_one_bit():
    assert shannon_entropy("ab") == 1.0


def test_four_uniform_symbols_is_two_bits():
    assert shannon_entropy("abcd") == 2.0


def test_known_value():
    # "aabb": P(a)=0.5, P(b)=0.5 -> H = 1.0
    assert math.isclose(shannon_entropy("aabb"), 1.0)


def test_high_entropy_random_string():
    rng = random.Random(42)
    s = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(64))
    assert shannon_entropy(s) > 4.5


def test_low_entropy_placeholder():
    assert shannon_entropy("sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") < 3.0


def test_longer_uniform_same_entropy():
    assert math.isclose(shannon_entropy("abab"), shannon_entropy("ab" * 100))
