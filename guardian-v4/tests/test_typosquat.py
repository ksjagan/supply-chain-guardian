"""Tests for typosquatting heuristics and edit distance."""
from guardian import hunter


def test_edit_distance():
    assert hunter.edit_distance("react", "recat") <= 2
    assert hunter.edit_distance("lodash", "lodahs") == 2
    assert hunter.edit_distance("express", "express") == 0
    assert hunter.edit_distance("completelydifferent", "express") > 2


def test_typosquat_detection():
    # 'recat' is distance 2 from 'react'
    res = hunter.typosquat_check("recat")
    assert res is not None
    assert res["similar_to"] == "react"

    # 'lodahs' is distance 2 from 'lodash'
    res2 = hunter.typosquat_check("lodahs")
    assert res2 is not None
    assert res2["similar_to"] == "lodash"

    # Exact popular package is not a typosquat of itself
    assert hunter.typosquat_check("react") is None
    assert hunter.typosquat_check("lodash") is None
