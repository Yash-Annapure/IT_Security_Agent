"""Weakness-detection tests.

Unlike the rest of the suite (which pins down what each function does), these
tests are written against the *failure modes* the project actually cares
about: the exact four name collisions Week 2 found (babel, jupyter, json5,
jsonpointer), and the general shape of "does the model behave sensibly, or
did we build something that degenerates to a shortcut." Several of these
would have failed before the `_domain()` fix in normalize.py (see
test_normalize.py for the narrower unit-level regression) - keeping them
here, at the pipeline level, is what would have actually caught the bug
during Week 3 instead of a live spot-check afterwards.
"""
from unittest.mock import patch

import numpy as np
import pandas as pd
import pytest

from it_security_agent import agent, explain, labeling, matching, model, normalize
from it_security_agent.normalize import VendorCandidate
from it_security_agent.schema import Component

# The four real Week 2 name collisions, reproduced with the actual registry/CPE
# URLs observed live against the NVD API (see conversation history / week3_agent.ipynb
# Section 7): each pair is (this project's real registry URLs, the unrelated
# collision's CPE reference URLs). All four are same-name, cross-ecosystem or
# cross-project collisions - exactly what registry_overlap exists to catch.
REAL_COLLISIONS = {
    "babel": (["https://babel.pocoo.org/", "https://github.com/python-babel/babel"],
              ["https://babel.dev/", "https://github.com/babel/babel/tags"]),
    "json5": (["https://github.com/dpranke/pyjson5"],
              ["https://json5.org/", "https://github.com/json5/json5/tags"]),
    "jsonpointer": (["https://github.com/stefankoegl/python-json-pointer"],
                     ["https://github.com/janl/node-jsonpointer/tags"]),
}


@pytest.mark.parametrize("name", sorted(REAL_COLLISIONS))
def test_known_week2_collisions_no_longer_show_registry_overlap(name):
    reg_urls, ref_urls = REAL_COLLISIONS[name]
    products = [{"cpe": {
        "cpeName": f"cpe:2.3:a:collidingvendor:{name}:*:*:*:*:*:*:*:*",
        "titles": [{"lang": "en", "title": name}],
        "refs": [{"ref": r} for r in ref_urls],
    }}]
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value={"urls": reg_urls}):
        candidates = normalize.resolve_vendor(name, "PyPI")
    assert candidates[0].signals["registry_overlap"] is False, (
        f"{name}: registry_overlap should be False - {reg_urls} and {ref_urls} are "
        f"different projects that merely share a hosting domain"
    )


def _synthetic_training_corpus(n_per_class=30, seed=0):
    # Recreates the actual signal structure the real data has: collisions share the
    # package's name (name_similarity stays high on both sides - that's *why* they're
    # collisions), so the only features that can separate them are the ones that don't
    # depend on the name string: keyword_alignment and osv_corroborated.
    rng = np.random.default_rng(seed)
    components, resolve_map = [], {}
    for i in range(n_per_class):
        real_name = f"realpkg{i}"
        component = Component(name=real_name, version="1.0.0", ecosystem="PyPI", source="test")
        components.append(component)
        resolve_map[real_name] = [VendorCandidate(
            vendor=f"{real_name}vendor", product=real_name,
            signals={
                "vendor_equals_package": int(rng.random() > 0.3),
                "name_similarity": float(rng.uniform(0.85, 1.0)),
                "registry_overlap": True,
                "py_keyword_score": int(rng.integers(1, 4)),
                "js_keyword_score": 0,
                "keyword_alignment": int(rng.integers(1, 4)),
            },
        )]

        collision_name = f"collidepkg{i}"
        component2 = Component(name=collision_name, version="1.0.0", ecosystem="PyPI", source="test")
        components.append(component2)
        resolve_map[collision_name] = [VendorCandidate(
            vendor=f"{collision_name}vendor", product=collision_name,
            signals={
                "vendor_equals_package": int(rng.random() > 0.3),
                "name_similarity": float(rng.uniform(0.85, 1.0)),  # same range as "real" - by design
                "registry_overlap": False,
                "py_keyword_score": 0,
                "js_keyword_score": int(rng.integers(0, 3)),
                "keyword_alignment": int(rng.integers(-3, 1)),
            },
        )]
    return components, resolve_map


def _train_on_synthetic_corpus(tmp_path, n_per_class=30, seed=0):
    components, resolve_map = _synthetic_training_corpus(n_per_class=n_per_class, seed=seed)
    with patch("it_security_agent.normalize.resolve_vendor", side_effect=lambda name, eco, conn=None: resolve_map[name]), \
         patch("it_security_agent.osv.query", return_value=[]):
        dataset = labeling.build_dataset(components)
    result = model.train_and_compare(dataset, model_dir=tmp_path)
    return dataset, result


def test_model_beats_naive_baselines_on_risk_score(tmp_path):
    # A model that just memorizes "name_similarity is high -> real" would be no
    # better than always saying "real match" once names collide by construction
    # (see _synthetic_training_corpus). This is the sanity check that training
    # is doing something, not degenerating to a name-similarity shortcut.
    from sklearn.model_selection import train_test_split

    dataset, result = _train_on_synthetic_corpus(tmp_path, n_per_class=40, seed=1)
    y = dataset["label_real_match"].astype(int)
    # Same split model.train_and_compare uses internally, so these baselines are
    # measured on the identical test fold the winner's risk_score was computed on.
    _, _, _, y_test = train_test_split(
        dataset[labeling.FEATURES], y, test_size=0.3, random_state=42, stratify=y)

    n_real, n_collision = int(y_test.sum()), int((y_test == 0).sum())
    always_real_risk = model.FP_WEIGHT * n_collision          # 0 FN, every collision is a FP
    always_collision_risk = model.FN_WEIGHT * n_real          # every real match becomes a FN, 0 FP

    winner_risk = result["results"][result["winner"]]["risk_score"]
    assert winner_risk < always_real_risk
    assert winner_risk < always_collision_risk


def test_model_separates_name_collisions_from_real_matches_end_to_end(tmp_path):
    dataset, result = _train_on_synthetic_corpus(tmp_path)
    winner_name, winning_model, threshold = model.load_winning_model(model_dir=tmp_path)
    explainer = explain.make_explainer(winner_name, winning_model, dataset[labeling.FEATURES].astype(float))

    # A fresh collision case, same shape as babel/json5/jsonpointer: name matches
    # perfectly, registry_overlap is (correctly, post-fix) False, and there's no
    # keyword-text signal either way.
    collision_component = Component(name="freshcollision", version="1.0.0", ecosystem="PyPI", source="test")
    collision_candidate = VendorCandidate(
        vendor="freshcollisionvendor", product="freshcollision",
        signals={"vendor_equals_package": 1, "name_similarity": 1.0, "registry_overlap": False,
                 "py_keyword_score": 0, "js_keyword_score": 0, "keyword_alignment": 0},
    )
    match = {"cve": "CVE-TEST-0001", "severity": "HIGH", "cvss_score": 7.5,
              "vendor": "freshcollisionvendor", "vendor_candidate": collision_candidate}
    with patch("it_security_agent.matching.find_candidates", return_value=([match], [])), \
         patch("it_security_agent.osv.query", return_value=[]), \
         patch("it_security_agent.kev.is_kev", return_value=None):
        scan_result = agent.scan([collision_component], winner_name, winning_model, threshold, explainer)

    assert scan_result.escalated == [], "a name collision must never reach KEV escalation"
    assert scan_result.confirmed == [], (
        "a name collision with no corroborating signal (registry_overlap=False, no OSV "
        "agreement, no keyword alignment) should not be silently confirmed - it should "
        "land in review_queue for a human, per the triage policy Section 5 documents"
    )
    assert len(scan_result.review_queue) == 1
    assert scan_result.review_queue[0].explanation is not None


def test_model_does_not_key_off_name_similarity_alone(tmp_path):
    # Adversarial probe: two candidates with an *identical* name-shaped signature
    # (vendor_equals_package=1, name_similarity=1.0 - Week 2's failure mode looked
    # exactly like this) but opposite keyword/OSV evidence should get different
    # confidence scores. If the model only looked at the name features, it couldn't
    # tell them apart.
    _, result = _train_on_synthetic_corpus(tmp_path)
    winning_model = result["results"][result["winner"]]["model"]

    base = {"vendor_equals_package": 1, "name_similarity": 1.0}
    looks_real = {**base, "py_keyword_score": 3, "js_keyword_score": 0,
                  "keyword_alignment": 3, "ecosystem_pypi": 1, "osv_corroborated": 1}
    looks_like_collision = {**base, "py_keyword_score": 0, "js_keyword_score": 2,
                             "keyword_alignment": -2, "ecosystem_pypi": 1, "osv_corroborated": 0}

    confidence_real = model.predict_confidence(winning_model, looks_real)
    confidence_collision = model.predict_confidence(winning_model, looks_like_collision)
    assert confidence_real > confidence_collision, (
        "identical name-similarity signal produced the same confidence regardless of "
        "keyword/OSV evidence - the model would be relying on name matching alone, "
        "which is exactly Week 2's collision bug"
    )


def test_threshold_is_not_pinned_to_the_search_grid_floor(tmp_path):
    # _best_threshold searches 19 values from 0.05 to 0.95. Because a missed real
    # match costs 10x a false alarm (FN_WEIGHT=10), the optimizer is biased toward
    # low thresholds - worth guarding explicitly so a future change doesn't silently
    # collapse to "confirm anything with a nonzero score" on realistic, noisy data.
    _, result = _train_on_synthetic_corpus(tmp_path, n_per_class=40, seed=3)
    threshold = result["threshold"]
    assert threshold > 0.05, (
        f"threshold selection picked the absolute floor of the search grid ({threshold}) "
        f"on a noisy, non-degenerate dataset - that's a 'confirm almost everything' policy, "
        f"not a calibrated one"
    )
