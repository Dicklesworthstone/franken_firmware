"""Synthetic worlds for the planning-reconcile cases (P01-REC-*). A world is a (live, generated) pair that agrees in every compared
field; a plant changes exactly one thing and names the codes `planning_reconcile.reconcile` must then report, written out by
hand from the rules. Nothing here reads the real tracker or the real planning files: the permitted positive and every planted
negative must hold on data that exists only in this file, so the verdict cannot depend on what the tracker happens to hold."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import tempfile
from typing import Any, Callable, Dict, List, Tuple

import planning_reconcile as pr

REQUIRED_FEATURES = ["airplay2", "alexa_bridge", "protected_render", "spotify_connect", "synchronized_groups", "tailnet_native"]


def registry_block(names=None):
    return (pr.FEATURES_BEGIN + "\n```json\n" + json.dumps({"required_features": REQUIRED_FEATURES if names is None else names})
            + "\n```\n" + pr.FEATURES_END)


def workspace_contract():
    return {"features": [{"name": name, "requirement": "required"} for name in REQUIRED_FEATURES]
            + [{"name": name, "requirement": "optional"} for name in ("artwork", "virtual_house_harness")]}

OLD, NEW = "2026-11-04T10:00:00Z", "2026-11-05T10:00:00Z"
TASKS = [  # key, title, deps, design packages
    ("A", "the root", [], []),
    ("B", "depends on the root", ["A"], ["INT-001"]),
    ("G", "a gate", ["A"], ["INT-002", "R02"]),
    ("T", "gated by G", ["B", "G"], ["INT-001"]),
    ("P01", "workspace contract", [], []),
]
IDS = {"A": "ffw-aa1", "B": "ffw-bb2", "G": "ffw-gg3", "T": "ffw-tt4", "P01": "ffw-pp1"}
Pair = Tuple[Dict[str, Any], Dict[str, Any]]


def _description(key: str, title: str, packages: List[str]) -> str:
    line = ", ".join(packages) if packages else pr.STANDALONE
    return (f"# {key}: {title}\n\nGoal: a synthetic goal for {key}.\n\nMapped design packages: {line}.\n"
            + ("\n" + registry_block() + "\n" if key == "P01" else ""))


def world() -> Pair:
    """A live document (with a complete pagination envelope) and the generated planning files, in full agreement."""
    issues, catalog, snapshot, alias = [], [], [], {}
    for key, title, deps, packages in TASKS:
        issue_id, description = IDS[key], _description(key, title, packages)
        alias[key] = issue_id
        catalog.append({"key": key, "title": title, "deps": list(deps), "design_packages": list(packages)})
        snapshot.append({"id": issue_id, "title": f"{key}: {title}", "description": description,
                         "acceptance_criteria": f"- [ ] {key} accepts the permitted case", "updated_at": OLD})
        if key == "P01":
            catalog[-1]["required_features"] = list(REQUIRED_FEATURES)
            snapshot[-1]["required_features"] = list(REQUIRED_FEATURES)
        issues.append({"id": issue_id, "title": f"{key}: {title}", "description": description,
                       "acceptance_criteria": f"- [ ] {key} accepts the permitted case", "updated_at": NEW,
                       "dependencies": [{"issue_id": issue_id, "depends_on_id": IDS[dep], "type": "blocks"} for dep in deps]})
    live = {"issues": issues, "envelope": {"total": len(issues), "limit": 0, "offset": 0, "has_more": False}}
    return live, {"catalog": catalog, "map": alias, "snapshot": snapshot, "workspace_contract": workspace_contract()}


def _issue(live: Dict[str, Any], key: str) -> Dict[str, Any]:
    return next(issue for issue in live["issues"] if issue["id"] == IDS[key])


def _row(generated: Dict[str, Any], key: str) -> Dict[str, Any]:
    return next(row for row in generated["snapshot"] if row["id"] == IDS[key])


def _task(generated: Dict[str, Any], key: str) -> Dict[str, Any]:
    return next(task for task in generated["catalog"] if task["key"] == key)


def _a_required_task_nobody_generated(live, generated):
    live["issues"].append({"id": "ffw-zz9", "title": "Z: a required task added to the tracker later", "description": "# Z\n",
                           "acceptance_criteria": "- [ ] Z", "updated_at": NEW,
                           "dependencies": [{"issue_id": "ffw-zz9", "depends_on_id": IDS["A"], "type": "blocks"}]})
    live["envelope"]["total"] += 1


def _only_the_acceptance_criteria_changed(live, generated):
    _issue(live, "B")["acceptance_criteria"] = "- [ ] B accepts something else entirely"


def _the_gate_edge_removed(live, generated):
    _issue(live, "T")["dependencies"] = [e for e in _issue(live, "T")["dependencies"] if e["depends_on_id"] != IDS["G"]]


def _paginated_has_more(live, generated):
    live["envelope"]["has_more"] = True


def _paginated_second_page(live, generated):
    live["envelope"]["offset"] = 2


def _paginated_total_larger_than_the_page(live, generated):
    live["envelope"]["total"] = len(live["issues"]) + 1


def _stale_issue(live, generated):
    _issue(live, "B")["updated_at"] = "2026-11-03T10:00:00Z"


def _description_changed(live, generated):
    _issue(live, "B")["description"] = _issue(live, "B")["description"].replace("synthetic goal", "different goal")


def _title_changed(live, generated):
    _issue(live, "B")["title"] = "B: a title someone edited in the tracker"


def _two_keys_one_issue(live, generated):
    generated["map"]["X"] = IDS["B"]
    generated["catalog"].append({"key": "X", "title": "depends on the root", "deps": ["A"], "design_packages": ["INT-001"]})


def _catalog_key_without_alias(live, generated):
    del generated["map"]["T"]


def _alias_for_a_key_the_catalog_lacks(live, generated):
    generated["map"]["Q"] = "ffw-qq5"


def _catalog_task_missing_from_live(live, generated):
    live["issues"] = [i for i in live["issues"] if i["id"] != IDS["A"]]
    live["envelope"]["total"] -= 1


def _snapshot_lacks_the_issue(live, generated):
    generated["snapshot"] = [r for r in generated["snapshot"] if r["id"] != IDS["B"]]


def _generated_has_no_acceptance_criteria(live, generated):
    del _row(generated, "B")["acceptance_criteria"]


def _design_packages_differ(live, generated):
    _task(generated, "B")["design_packages"] = ["INT-009"]


def _edge_has_another_type(live, generated):
    for edge in _issue(live, "T")["dependencies"]:
        if edge["depends_on_id"] == IDS["G"]:
            edge["type"] = "parent-child"


def _an_edge_only_live_has(live, generated):
    _issue(live, "B")["dependencies"].append({"issue_id": IDS["B"], "depends_on_id": IDS["G"], "type": "blocks"})


def _registry_text(live, generated, replacement):
    for row in (_issue(live, "P01"), _row(generated, "P01")):
        row["description"] = row["description"].replace(registry_block(), replacement)


def _registry_missing(live, generated):
    _registry_text(live, generated, "")


def _registry_malformed(live, generated):
    _registry_text(live, generated, pr.FEATURES_BEGIN + "\n```json\n{not JSON}\n```\n" + pr.FEATURES_END)


def _registry_duplicate_name(live, generated):
    _registry_text(live, generated, registry_block(REQUIRED_FEATURES + ["tailnet_native"]))


def _registry_duplicate_block(live, generated):
    _registry_text(live, generated, registry_block() + "\n" + registry_block())


def _registry_duplicate_json_key(live, generated):
    _registry_text(live, generated, pr.FEATURES_BEGIN + '\n```json\n{"required_features":["airplay2"],"required_features":["tailnet_native"]}\n```\n' + pr.FEATURES_END)


def _live_required_feature_removed(live, generated):
    _registry_text(live, generated, registry_block([n for n in REQUIRED_FEATURES if n != "tailnet_native"]))


def _catalog_projection_missing(live, generated):
    del _task(generated, "P01")["required_features"]


def _snapshot_projection_drift(live, generated):
    _row(generated, "P01")["required_features"].remove("tailnet_native")


def _projection_duplicate(live, generated):
    _task(generated, "P01")["required_features"].append("tailnet_native")


def _native_feature_missing(live, generated):
    generated["workspace_contract"]["features"] = [s for s in generated["workspace_contract"]["features"] if s["name"] != "tailnet_native"]


def _native_feature_demoted(live, generated):
    next(s for s in generated["workspace_contract"]["features"] if s["name"] == "tailnet_native")["requirement"] = "optional"


def _optional_feature_promoted_only_in_contract(live, generated):
    next(s for s in generated["workspace_contract"]["features"] if s["name"] == "artwork")["requirement"] = "required"


def _contract_duplicate_feature(live, generated):
    generated["workspace_contract"]["features"].append({"name": "tailnet_native", "requirement": "required"})


# name -> (what it changes, plant, the codes that must result: written by hand from the rules in planning_reconcile.py)
PLANTS: Dict[str, Tuple[str, Callable[[Dict[str, Any], Dict[str, Any]], None], List[str]]] = {
    "required_task_absent_from_catalog": ("a live task the catalog never had, with a dependency", _a_required_task_nobody_generated,
                                          ["live_edge_not_in_generated", "task_absent_from_catalog"]),
    "only_acceptance_criteria_changed": ("one live acceptance_criteria, nothing else", _only_the_acceptance_criteria_changed,
                                         ["acceptance_criteria_differs"]),
    "gate_edge_removed": ("the live edge from T to its gate G", _the_gate_edge_removed, ["blocking_edge_missing_in_live"]),
    "paginated_has_more": ("a live export that says there is more", _paginated_has_more, ["live_export_incomplete"]),
    "paginated_second_page": ("a live export that starts at offset 2", _paginated_second_page, ["live_export_incomplete"]),
    "paginated_total_larger": ("a live export whose total exceeds its rows", _paginated_total_larger_than_the_page,
                               ["live_export_incomplete"]),
    "stale_export": ("a live issue older than the generated copy of it", _stale_issue, ["live_export_stale"]),
    "description_changed": ("one live description", _description_changed, ["description_differs"]),
    "title_changed": ("one live title", _title_changed, ["title_differs"]),
    "two_keys_one_issue": ("a second catalog key mapped to B's issue", _two_keys_one_issue, ["alias_not_unique", "title_differs"]),
    "catalog_key_without_alias": ("a catalog key with no alias entry", _catalog_key_without_alias,
                                  ["alias_unmapped_key", "live_edge_not_in_generated", "task_absent_from_catalog"]),
    "alias_for_unknown_key": ("an alias entry for a key the catalog lacks", _alias_for_a_key_the_catalog_lacks,
                              ["alias_stale_key", "catalog_task_not_live"]),
    "catalog_task_missing_from_live": ("the root task removed from the live data", _catalog_task_missing_from_live,
                                       ["catalog_task_not_live"]),
    "snapshot_lacks_issue": ("the generated snapshot without one issue", _snapshot_lacks_the_issue, ["snapshot_missing_issue"]),
    "generated_without_acceptance": ("a generated snapshot row without acceptance_criteria", _generated_has_no_acceptance_criteria,
                                     ["acceptance_criteria_absent_from_generated"]),
    "design_packages_differ": ("the catalog's design packages for one task", _design_packages_differ,
                               ["design_package_alias_differs"]),
    "edge_type_differs": ("the live gate edge typed parent-child", _edge_has_another_type, ["edge_type_differs"]),
    "edge_only_live_has": ("an extra blocking edge in the live data", _an_edge_only_live_has, ["live_edge_not_in_generated"]),
    "registry_missing": ("the live P01 authority absent, with its description faithfully copied", _registry_missing,
                         ["required_feature_registry_missing"]),
    "registry_malformed": ("the live authority is not JSON", _registry_malformed, ["required_feature_registry_invalid"]),
    "registry_duplicate_name": ("the authority lists a feature twice", _registry_duplicate_name, ["required_feature_registry_invalid"]),
    "registry_duplicate_block": ("two competing live authority blocks", _registry_duplicate_block, ["required_feature_registry_invalid"]),
    "registry_duplicate_json_key": ("ambiguous duplicate JSON required_features keys", _registry_duplicate_json_key,
                                    ["required_feature_registry_invalid"]),
    "live_required_feature_removed": ("tailnet removed only from the live required list", _live_required_feature_removed,
                                     ["required_feature_not_live", "required_feature_projection_differs"]),
    "catalog_projection_missing": ("no required list in the P01 catalog row", _catalog_projection_missing,
                                   ["required_feature_projection_missing"]),
    "snapshot_projection_drift": ("tailnet lost from the generated snapshot projection", _snapshot_projection_drift,
                                  ["required_feature_projection_differs"]),
    "projection_duplicate": ("a duplicate feature in the catalog projection", _projection_duplicate,
                             ["required_feature_projection_invalid"]),
    "native_feature_missing": ("tailnet absent from the actual workspace contract", _native_feature_missing,
                              ["required_feature_missing_from_contract"]),
    "native_feature_demoted": ("native tailnet demoted to optional", _native_feature_demoted, ["required_feature_demoted"]),
    "optional_feature_promoted_only_in_contract": ("artwork required in the contract but optional in live authority",
                                                  _optional_feature_promoted_only_in_contract, ["required_feature_not_live"]),
    "contract_duplicate_feature": ("duplicate workspace feature declarations", _contract_duplicate_feature,
                                   ["workspace_feature_registry_invalid"]),
}
GROUPS: Dict[str, List[str]] = {
    "required_task_absent": ["required_task_absent_from_catalog"],
    "acceptance_only": ["only_acceptance_criteria_changed"],
    "gate_edge": ["gate_edge_removed"],
    "stale_or_paginated": ["paginated_has_more", "paginated_second_page", "paginated_total_larger", "stale_export"],
    "every_other_compared_field": ["description_changed", "title_changed", "two_keys_one_issue", "catalog_key_without_alias",
                                   "alias_for_unknown_key", "catalog_task_missing_from_live", "snapshot_lacks_issue",
                                   "generated_without_acceptance", "design_packages_differ", "edge_type_differs",
                                   "edge_only_live_has"],
    "required_features": ["registry_missing", "registry_malformed", "registry_duplicate_name", "registry_duplicate_block",
                          "registry_duplicate_json_key", "live_required_feature_removed", "catalog_projection_missing",
                          "snapshot_projection_drift", "projection_duplicate", "native_feature_missing", "native_feature_demoted",
                          "optional_feature_promoted_only_in_contract", "contract_duplicate_feature"],
}


def planted(name: str) -> Pair:
    live, generated = world()
    before = copy.deepcopy((live, generated))
    PLANTS[name][1](live, generated)
    if (live, generated) == before:
        raise AssertionError(f"plant {name} changed nothing")
    return live, generated


def _write_world(directory: str, live: Dict[str, Any], generated: Dict[str, Any]) -> Tuple[str, str]:
    """The world as files in the shapes the CLI reads: a live JSON document and a planning directory."""
    planning = os.path.join(directory, "planning")
    os.makedirs(planning)
    for name, doc in (("task-catalog.json", generated["catalog"]), ("bead-map.json", generated["map"]),
                      ("beads-snapshot.json", {"issues": generated["snapshot"]})):
        with open(os.path.join(planning, name), "w", encoding="utf-8") as f:
            json.dump(doc, f)
    live_path = os.path.join(directory, "live.json")
    with open(live_path, "w", encoding="utf-8") as f:
        json.dump({"issues": live["issues"], **(live["envelope"] or {})}, f)
    return live_path, planning


def _cli(live_path: str, planning: str) -> int:
    with contextlib.redirect_stdout(io.StringIO()):
        return pr.main(["--live", live_path, "--planning", planning])


def judge_positive() -> str:
    """A catalog that matches live data passes: in memory, and as files through the command line (exit 0). The same files with
    one acceptance_criteria changed exit 1, so the command line is not a rubber stamp."""
    live, generated = world()
    if pr.reconcile(live, generated, generated["workspace_contract"]):
        raise AssertionError("the unplanted world is not clean")
    with tempfile.TemporaryDirectory(prefix="p01-rec-") as tmp:
        live_path, planning = _write_world(tmp, live, generated)
        if _cli(live_path, planning) != 0:
            raise AssertionError("the command line rejected a matching world")
    live, generated = planted("only_acceptance_criteria_changed")
    with tempfile.TemporaryDirectory(prefix="p01-rec-") as tmp:
        live_path, planning = _write_world(tmp, live, generated)
        if _cli(live_path, planning) != 1:
            raise AssertionError("the command line accepted a world whose acceptance_criteria differ")
    return "the matching world is clean in memory and through the command line (exit 0); the planted one exits 1"


def judge_group(group: str) -> str:
    """The permitted positive holds, and every plant of the group reports exactly its hand-written codes. Raises AssertionError."""
    live, generated = world()
    clean = pr.reconcile(live, generated, generated["workspace_contract"])
    if clean:
        raise AssertionError(f"the unplanted world is not clean: {clean}")
    for name in GROUPS[group]:
        live, generated = planted(name)
        got = pr.codes(pr.reconcile(live, generated, generated["workspace_contract"]))
        want = sorted(PLANTS[name][2])
        if got != want:
            raise AssertionError(f"plant {name} ({PLANTS[name][0]}): codes {got}, want {want}")
    return f"{len(GROUPS[group])} plant(s), each failing with exactly its codes; the unplanted world is clean"
