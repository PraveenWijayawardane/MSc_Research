#!/usr/bin/env python3
"""
Chapter 6 final evaluation helper for the healthcare risk-engine project.

Purpose
-------
Reads archived controlled-run evidence under evaluation/chapter6/final/<RunID>/,
isolates scenario-relevant Wazuh and Zeek events, re-scores the isolated evidence
with the current ContextualRiskEngine, and produces one run-level prediction for:

1. Severity-only host baseline
2. Network-only contextual analysis
3. Contextual analysis without correlation
4. Full proposed framework

It then writes binary metrics, four-class metrics, confusion matrices and
correlation summaries used by Chapter 6.

This script deliberately evaluates ONE prediction per controlled run rather than
one prediction per raw event, so high-volume scenarios do not dominate metrics.

Expected per-run files
----------------------
run_info.json
live_wazuh_events.json
live_zeek_conn.json

Optional run_info.json field for controlled timestamp replay:
    "evaluation_start_utc": "2026-08-10T04:30:00Z"

When present, the isolated evidence is shifted by the same delta so that the
original run start maps to evaluation_start_utc. Relative event spacing is
preserved. This is intended only for explicitly documented temporal-context
replay experiments; the original archived evidence is never modified.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import math
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from risk_engine import (  # noqa: E402
    ContextualRiskEngine,
    normalize_wazuh_input,
    normalize_zeek_input,
    parse_timestamp,
)

CLASS_ORDER = [
    "Legitimate",
    "Low Suspicion",
    "Suspicious",
    "Likely Malicious",
]
CLASS_RANK = {name: index for index, name in enumerate(CLASS_ORDER)}
POSITIVE_CLASSES = {"Suspicious", "Likely Malicious"}
VARIANTS = [
    "Severity-only host baseline",
    "Network-only contextual analysis",
    "Contextual analysis without correlation",
    "Full proposed framework",
]


@dataclass(frozen=True)
class ScenarioDefinition:
    scenario_id: str
    ground_truth: str
    expected_class: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    wazuh_agent_ips: tuple[str, ...]
    wazuh_keywords: tuple[str, ...]
    require_wazuh: bool
    require_zeek: bool
    expected_correlation: bool


DEFAULT_SCENARIOS: tuple[ScenarioDefinition, ...] = (
    ScenarioDefinition(
        "B1", "Benign", "Legitimate",
        "192.168.100.30", "192.168.100.40", 5432, "tcp",
        ("192.168.100.30", "192.168.100.40"), (),
        False, True, False,
    ),
    ScenarioDefinition(
        "B2", "Benign", "Low Suspicion",
        "192.168.100.21", "192.168.100.30", 22, "tcp",
        ("192.168.100.30",), (),
        False, True, False,
    ),
    ScenarioDefinition(
        "A1", "Attack", "Likely Malicious",
        "192.168.100.20", "192.168.100.40", 22, "tcp",
        ("192.168.100.40",),
        ("authentication failure", "failed password", "login failed", "invalid user"),
        True, True, True,
    ),
    ScenarioDefinition(
        "A2", "Attack", "Suspicious",
        "192.168.100.20", "192.168.100.40", 5432, "tcp",
        ("192.168.100.40",), (),
        False, True, False,
    ),
    ScenarioDefinition(
        "A3", "Attack", "Suspicious",
        "192.168.100.20", "192.168.100.30", 22, "tcp",
        ("192.168.100.30",), (),
        False, True, False,
    ),
    ScenarioDefinition(
        "A4", "Attack", "Suspicious",
        "192.168.100.20", "192.168.100.50", 445, "tcp",
        ("192.168.100.50",), (),
        False, True, False,
    ),
    ScenarioDefinition(
        "A5", "Attack", "Likely Malicious",
        "192.168.100.30", "192.168.100.40", 5432, "tcp",
        ("192.168.100.30",),
        ("privilege escalation", "root session", "sudo", "user changed to root"),
        True, True, True,
    ),
    ScenarioDefinition(
        "U1", "Attack", "Suspicious",
        "192.168.101.60", "192.168.100.40", 5432, "tcp",
        ("192.168.100.40",), (),
        False, True, False,
    ),
)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False, default=str)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_iso(value: Any) -> datetime:
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError(f"Invalid timestamp: {value!r}")
    return parsed


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def bool_text(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def split_multi(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(";") if part.strip())


def write_default_scenario_csv(path: Path) -> None:
    rows = []
    for s in DEFAULT_SCENARIOS:
        rows.append({
            "ScenarioID": s.scenario_id,
            "GroundTruth": s.ground_truth,
            "ExpectedClass": s.expected_class,
            "SourceIP": s.source_ip,
            "DestinationIP": s.destination_ip,
            "DestinationPort": s.destination_port,
            "Protocol": s.protocol,
            "WazuhAgentIPs": ";".join(s.wazuh_agent_ips),
            "WazuhKeywords": ";".join(s.wazuh_keywords),
            "RequireWazuh": str(s.require_wazuh),
            "RequireZeek": str(s.require_zeek),
            "ExpectedCorrelation": str(s.expected_correlation),
        })
    write_csv(path, rows)


def load_scenarios(path: Path) -> dict[str, ScenarioDefinition]:
    if not path.exists():
        return {s.scenario_id: s for s in DEFAULT_SCENARIOS}
    result: dict[str, ScenarioDefinition] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            scenario_id = str(row.get("ScenarioID") or "").strip()
            if not scenario_id:
                continue
            result[scenario_id] = ScenarioDefinition(
                scenario_id=scenario_id,
                ground_truth=str(row.get("GroundTruth") or "").strip(),
                expected_class=str(row.get("ExpectedClass") or "").strip(),
                source_ip=str(row.get("SourceIP") or "").strip(),
                destination_ip=str(row.get("DestinationIP") or "").strip(),
                destination_port=int(float(row.get("DestinationPort") or 0)),
                protocol=str(row.get("Protocol") or "tcp").strip().lower(),
                wazuh_agent_ips=split_multi(str(row.get("WazuhAgentIPs") or "")),
                wazuh_keywords=tuple(k.lower() for k in split_multi(str(row.get("WazuhKeywords") or ""))),
                require_wazuh=bool_text(row.get("RequireWazuh")),
                require_zeek=bool_text(row.get("RequireZeek")),
                expected_correlation=bool_text(row.get("ExpectedCorrelation")),
            )
    return result


def scenario_id_from_run(run_info: dict[str, Any], run_dir: Path) -> str:
    explicit = str(run_info.get("scenario_id") or "").strip()
    if explicit:
        return explicit
    run_id = str(run_info.get("run_id") or run_dir.name).strip()
    return run_id.split("-", 1)[0]


def normalized_wazuh_text(event: dict[str, Any]) -> str:
    return json.dumps(event, ensure_ascii=False, default=str).lower()


def select_wazuh_events(
    raw_value: Any,
    engine: ContextualRiskEngine,
    scenario: ScenarioDefinition,
    start: datetime,
    end: datetime,
    padding: timedelta,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    lower = start - padding
    upper = end + padding
    for raw in normalize_wazuh_input(raw_value):
        if not isinstance(raw, dict):
            continue
        normal = engine._normalize_wazuh_event(raw)  # evaluation uses project normalization
        timestamp = parse_timestamp(normal.get("timestamp"))
        if timestamp is None or timestamp < lower or timestamp > upper:
            continue
        if scenario.wazuh_agent_ips and str(normal.get("ip") or "") not in scenario.wazuh_agent_ips:
            continue
        if scenario.wazuh_keywords:
            text = normalized_wazuh_text(normal)
            if not any(keyword in text for keyword in scenario.wazuh_keywords):
                continue
        selected.append(raw)
    return selected


def select_zeek_events(
    raw_value: Any,
    engine: ContextualRiskEngine,
    scenario: ScenarioDefinition,
    start: datetime,
    end: datetime,
    padding: timedelta,
    allow_reverse: bool,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    lower = start - padding
    upper = end + padding
    for raw in normalize_zeek_input(raw_value):
        if not isinstance(raw, dict):
            continue
        normal = engine._normalize_zeek_event(raw)  # evaluation uses project normalization
        timestamp = parse_timestamp(normal.get("timestamp"))
        if timestamp is None or timestamp < lower or timestamp > upper:
            continue
        src = str(normal.get("source_ip") or "")
        dst = str(normal.get("destination_ip") or "")
        port = int(normal.get("destination_port") or 0)
        protocol = str(normal.get("protocol") or "").lower()
        direct_match = (
            src == scenario.source_ip
            and dst == scenario.destination_ip
            and port == scenario.destination_port
            and (not scenario.protocol or protocol == scenario.protocol)
        )
        reverse_match = False
        if allow_reverse:
            reverse_match = (
                src == scenario.destination_ip
                and dst == scenario.source_ip
                and (not scenario.protocol or protocol == scenario.protocol)
            )
        if direct_match or reverse_match:
            selected.append(raw)
    return selected


def shift_wazuh_events(
    events: list[dict[str, Any]],
    engine: ContextualRiskEngine,
    delta: timedelta,
) -> list[dict[str, Any]]:
    shifted: list[dict[str, Any]] = []
    for raw in events:
        item = copy.deepcopy(raw)
        normal = engine._normalize_wazuh_event(item)
        old = parse_timestamp(normal.get("timestamp"))
        if old is None:
            shifted.append(item)
            continue
        value = iso_utc(old + delta)
        source = item.get("_source") if isinstance(item.get("_source"), dict) else item
        if "timestamp" in source:
            source["timestamp"] = value
        elif "@timestamp" in source:
            source["@timestamp"] = value
        else:
            source["timestamp"] = value
        shifted.append(item)
    return shifted


def shift_zeek_events(
    events: list[dict[str, Any]],
    engine: ContextualRiskEngine,
    delta: timedelta,
) -> list[dict[str, Any]]:
    shifted: list[dict[str, Any]] = []
    for raw in events:
        item = copy.deepcopy(raw)
        normal = engine._normalize_zeek_event(item)
        old = parse_timestamp(normal.get("timestamp"))
        if old is None:
            shifted.append(item)
            continue
        new_time = old + delta
        if "ts" in item:
            old_ts = item.get("ts")
            try:
                float(old_ts)
                item["ts"] = round(new_time.timestamp(), 6)
            except (TypeError, ValueError):
                item["ts"] = iso_utc(new_time)
        if "timestamp" in item:
            item["timestamp"] = iso_utc(new_time)
        if "@timestamp" in item:
            item["@timestamp"] = iso_utc(new_time)
        if not any(key in item for key in ("ts", "timestamp", "@timestamp")):
            item["timestamp"] = iso_utc(new_time)
        shifted.append(item)
    return shifted


def severity_class(rule_level: int) -> str:
    """Evaluation-only raw Wazuh severity baseline mapping."""
    if rule_level >= 12:
        return "Likely Malicious"
    if rule_level >= 8:
        return "Suspicious"
    if rule_level >= 5:
        return "Low Suspicion"
    return "Legitimate"


def score_event(event: dict[str, Any] | None) -> int:
    if not event:
        return 0
    try:
        return int(float(event.get("risk_score") or 0))
    except (TypeError, ValueError):
        return 0


def highest_event(events: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    items = [event for event in events if isinstance(event, dict)]
    if not items:
        return None
    return max(
        items,
        key=lambda event: (
            score_event(event),
            CLASS_RANK.get(str(event.get("classification") or ""), -1),
            str(event.get("event_id") or ""),
        ),
    )


def final_full_events(output: dict[str, Any]) -> list[dict[str, Any]]:
    wazuh = [e for e in output.get("wazuh_results", []) if isinstance(e, dict)]
    network_by_id: dict[str, dict[str, Any]] = {}
    for event in output.get("zeek_results", []):
        if isinstance(event, dict) and event.get("event_id"):
            network_by_id[str(event["event_id"])] = event
    for event in output.get("correlated_results", []):
        if isinstance(event, dict) and event.get("event_id"):
            network_by_id[str(event["event_id"])] = event
    return wazuh + list(network_by_id.values())


def class_for_event(event: dict[str, Any] | None) -> str:
    if not event:
        return "Legitimate"
    value = str(event.get("classification") or "Legitimate")
    return value if value in CLASS_RANK else "Legitimate"


def binary_prediction(classification: str) -> str:
    return "Positive" if classification in POSITIVE_CLASSES else "Negative"


def safe_div(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def rounded(value: float | None, digits: int = 4) -> float | str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return ""
    return round(float(value), digits)


def compute_binary_metrics(predictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for variant in VARIANTS:
        tp = tn = fp = fn = 0
        for row in predictions:
            if not row["Accepted"]:
                continue
            truth_positive = row["GroundTruth"] == "Attack"
            pred_positive = row[f"{variant} Binary"] == "Positive"
            if truth_positive and pred_positive:
                tp += 1
            elif truth_positive and not pred_positive:
                fn += 1
            elif not truth_positive and pred_positive:
                fp += 1
            else:
                tn += 1
        total = tp + tn + fp + fn
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        f1 = None if precision is None or recall is None or (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
        rows.append({
            "Evaluation variant": variant,
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "Accuracy": rounded(safe_div(tp + tn, total)),
            "Precision": rounded(precision),
            "Recall": rounded(recall),
            "F1": rounded(f1),
            "FPR": rounded(safe_div(fp, fp + tn)),
            "FNR": rounded(safe_div(fn, fn + tp)),
            "AcceptedRuns": total,
        })
    return rows


def compute_binary_confusion(predictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for variant in VARIANTS:
        counts = Counter()
        for row in predictions:
            if not row["Accepted"]:
                continue
            actual = "Positive" if row["GroundTruth"] == "Attack" else "Negative"
            predicted = row[f"{variant} Binary"]
            counts[(actual, predicted)] += 1
        for actual in ("Negative", "Positive"):
            for predicted in ("Negative", "Positive"):
                rows.append({
                    "Evaluation variant": variant,
                    "Actual": actual,
                    "Predicted": predicted,
                    "Count": counts[(actual, predicted)],
                })
    return rows


def compute_multiclass_metrics(predictions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    metric_rows: list[dict[str, Any]] = []
    matrix_rows: list[dict[str, Any]] = []
    for variant in VARIANTS:
        accepted = [row for row in predictions if row["Accepted"]]
        predicted_key = f"{variant} Class"
        matrix = Counter((row["ExpectedClass"], row[predicted_key]) for row in accepted)
        class_metrics: list[tuple[float, float, float]] = []
        for actual in CLASS_ORDER:
            support = sum(matrix[(actual, pred)] for pred in CLASS_ORDER)
            tp = matrix[(actual, actual)]
            fp = sum(matrix[(other, actual)] for other in CLASS_ORDER if other != actual)
            fn = sum(matrix[(actual, pred)] for pred in CLASS_ORDER if pred != actual)
            precision = safe_div(tp, tp + fp)
            recall = safe_div(tp, tp + fn)
            f1 = None if precision is None or recall is None or (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
            confusions = Counter()
            for predicted in CLASS_ORDER:
                if predicted != actual and matrix[(actual, predicted)] > 0:
                    confusions[predicted] = matrix[(actual, predicted)]
            most_frequent = confusions.most_common(1)[0][0] if confusions else "NONE"
            metric_rows.append({
                "Evaluation variant": variant,
                "Classification": actual,
                "Support": support,
                "Precision": rounded(precision),
                "Recall": rounded(recall),
                "F1": rounded(f1),
                "Most frequent confusion": most_frequent,
            })
            if support > 0 and precision is not None and recall is not None and f1 is not None:
                class_metrics.append((precision, recall, f1))
        if class_metrics:
            metric_rows.append({
                "Evaluation variant": variant,
                "Classification": "Macro average",
                "Support": len(accepted),
                "Precision": rounded(sum(x[0] for x in class_metrics) / len(class_metrics)),
                "Recall": rounded(sum(x[1] for x in class_metrics) / len(class_metrics)),
                "F1": rounded(sum(x[2] for x in class_metrics) / len(class_metrics)),
                "Most frequent confusion": "–",
            })
        for actual in CLASS_ORDER:
            for predicted in CLASS_ORDER:
                matrix_rows.append({
                    "Evaluation variant": variant,
                    "ActualClass": actual,
                    "PredictedClass": predicted,
                    "Count": matrix[(actual, predicted)],
                })
    return metric_rows, matrix_rows


def correlation_outputs(predictions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    details: list[dict[str, Any]] = []
    expected_total = correct = missed = unexpected = 0
    non_expected_total = 0
    time_differences: list[float] = []
    for row in predictions:
        if not row["Accepted"]:
            continue
        expected = bool(row["ExpectedCorrelation"])
        observed = bool(row["ObservedCorrelation"])
        if expected:
            expected_total += 1
            if observed:
                correct += 1
            else:
                missed += 1
        else:
            non_expected_total += 1
            if observed:
                unexpected += 1
        if expected and observed and row["MinCorrelationMinutes"] != "":
            time_differences.append(float(row["MinCorrelationMinutes"]))
        details.append({
            "RunID": row["RunID"],
            "ScenarioID": row["ScenarioID"],
            "ExpectedCorrelation": expected,
            "ObservedCorrelation": observed,
            "CorrelatedEventCount": row["CorrelatedEventCount"],
            "MinCorrelationMinutes": row["MinCorrelationMinutes"],
            "HighestCorrelatedScore": row["HighestCorrelatedScore"],
            "HighestCorrelatedClass": row["HighestCorrelatedClass"],
        })
    summary = [{
        "ExpectedCorrelatedSequences": expected_total,
        "CorrectCorrelations": correct,
        "MissedCorrelations": missed,
        "UnexpectedCorrelatedRuns": unexpected,
        "CorrelationSuccessRate": rounded(safe_div(correct, expected_total)),
        "AccidentalCorrelationRate": rounded(safe_div(unexpected, non_expected_total)),
        "MedianMatchedTimeDifferenceMinutes": rounded(median(time_differences), 3) if time_differences else "",
        "AcceptedRuns": sum(1 for row in predictions if row["Accepted"]),
    }]
    return summary, details


def evaluate_run(
    run_dir: Path,
    scenario: ScenarioDefinition,
    engine: ContextualRiskEngine,
    output_root: Path,
    padding: timedelta,
    allow_reverse: bool,
) -> dict[str, Any]:
    run_info_path = run_dir / "run_info.json"
    wazuh_path = run_dir / "live_wazuh_events.json"
    zeek_path = run_dir / "live_zeek_conn.json"
    run_info = read_json(run_info_path)
    run_id = str(run_info.get("run_id") or run_dir.name)
    start = parse_iso(run_info["start_utc"])
    end = parse_iso(run_info["end_utc"])
    if end < start:
        raise ValueError(f"{run_id}: end_utc is earlier than start_utc")

    raw_wazuh = read_json(wazuh_path)
    raw_zeek = read_json(zeek_path)
    selected_wazuh = select_wazuh_events(raw_wazuh, engine, scenario, start, end, padding)
    selected_zeek = select_zeek_events(raw_zeek, engine, scenario, start, end, padding, allow_reverse)

    evaluation_start_raw = str(run_info.get("evaluation_start_utc") or "").strip()
    timestamp_replayed = bool(evaluation_start_raw)
    delta = timedelta(0)
    if timestamp_replayed:
        evaluation_start = parse_iso(evaluation_start_raw)
        delta = evaluation_start - start
        selected_wazuh = shift_wazuh_events(selected_wazuh, engine, delta)
        selected_zeek = shift_zeek_events(selected_zeek, engine, delta)

    filtered_dir = output_root / "filtered" / run_id
    write_json(filtered_dir / "wazuh.json", selected_wazuh)
    write_json(filtered_dir / "zeek.json", selected_zeek)

    output = engine.build_output(wazuh_data=selected_wazuh, zeek_data=selected_zeek)
    write_json(output_root / "scored" / f"{run_id}.json", output)

    normalized_wazuh = [engine._normalize_wazuh_event(raw) for raw in selected_wazuh]
    max_rule_level = max((int(event.get("rule_level") or 0) for event in normalized_wazuh), default=0)
    severity_cls = severity_class(max_rule_level)

    network_event = highest_event(output.get("zeek_results", []))
    no_corr_event = highest_event(
        list(output.get("wazuh_results", [])) + list(output.get("zeek_results", []))
    )
    full_event = highest_event(final_full_events(output))
    correlated_event = highest_event(output.get("correlated_results", []))

    network_cls = class_for_event(network_event)
    no_corr_cls = class_for_event(no_corr_event)
    full_cls = class_for_event(full_event)

    correlation_times = []
    for event in output.get("correlated_results", []):
        try:
            correlation_times.append(float(event.get("time_difference_minutes")))
        except (TypeError, ValueError):
            pass

    evidence_reasons = []
    if scenario.require_wazuh and not selected_wazuh:
        evidence_reasons.append("required Wazuh evidence missing")
    if scenario.require_zeek and not selected_zeek:
        evidence_reasons.append("required Zeek evidence missing")
    accepted = not evidence_reasons

    row: dict[str, Any] = {
        "RunID": run_id,
        "ScenarioID": scenario.scenario_id,
        "GroundTruth": scenario.ground_truth,
        "ExpectedClass": scenario.expected_class,
        "StartUTC": run_info.get("start_utc", ""),
        "EndUTC": run_info.get("end_utc", ""),
        "TimestampReplay": timestamp_replayed,
        "EvaluationStartUTC": evaluation_start_raw,
        "WazuhEvidenceCount": len(selected_wazuh),
        "ZeekEvidenceCount": len(selected_zeek),
        "Accepted": accepted,
        "ExclusionReason": "; ".join(evidence_reasons),
        "ExpectedCorrelation": scenario.expected_correlation,
        "ObservedCorrelation": bool(output.get("correlated_results")),
        "CorrelatedEventCount": len(output.get("correlated_results", [])),
        "MinCorrelationMinutes": rounded(min(correlation_times), 3) if correlation_times else "",
        "HighestCorrelatedScore": score_event(correlated_event) if correlated_event else "",
        "HighestCorrelatedClass": class_for_event(correlated_event) if correlated_event else "",
        "Severity-only host baseline Score": max_rule_level,
        "Severity-only host baseline Class": severity_cls,
        "Severity-only host baseline Binary": binary_prediction(severity_cls),
        "Network-only contextual analysis Score": score_event(network_event),
        "Network-only contextual analysis Class": network_cls,
        "Network-only contextual analysis Binary": binary_prediction(network_cls),
        "Contextual analysis without correlation Score": score_event(no_corr_event),
        "Contextual analysis without correlation Class": no_corr_cls,
        "Contextual analysis without correlation Binary": binary_prediction(no_corr_cls),
        "Full proposed framework Score": score_event(full_event),
        "Full proposed framework Class": full_cls,
        "Full proposed framework Binary": binary_prediction(full_cls),
    }
    return row


def validate_expected_runs(
    predictions: list[dict[str, Any]],
    scenarios: dict[str, ScenarioDefinition],
    expected_runs: int,
) -> list[str]:
    problems: list[str] = []
    accepted_counts = Counter(row["ScenarioID"] for row in predictions if row["Accepted"])
    total_counts = Counter(row["ScenarioID"] for row in predictions)
    for scenario_id in scenarios:
        if total_counts[scenario_id] != expected_runs:
            problems.append(
                f"{scenario_id}: found {total_counts[scenario_id]} run(s), expected {expected_runs}"
            )
        if accepted_counts[scenario_id] != expected_runs:
            problems.append(
                f"{scenario_id}: accepted {accepted_counts[scenario_id]} run(s), expected {expected_runs}"
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Chapter 6 final evaluation metrics")
    parser.add_argument("--environment", default="healthcare-lab")
    parser.add_argument(
        "--runs-dir",
        default=str(PROJECT_ROOT / "evaluation" / "chapter6" / "final"),
        help="Directory containing one subdirectory per controlled run",
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "evaluation" / "chapter6" / "derived" / "final"),
    )
    parser.add_argument(
        "--scenario-config",
        default=str(PROJECT_ROOT / "evaluation" / "chapter6" / "scenario_ground_truth.csv"),
    )
    parser.add_argument("--expected-runs-per-scenario", type=int, default=5)
    parser.add_argument("--time-padding-seconds", type=float, default=2.0)
    parser.add_argument("--allow-reverse-flow", action="store_true")
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument(
        "--write-default-scenarios",
        action="store_true",
        help="Write the thesis-aligned scenario CSV and exit",
    )
    args = parser.parse_args()

    scenario_path = Path(args.scenario_config).resolve()
    if args.write_default_scenarios:
        write_default_scenario_csv(scenario_path)
        print(f"Wrote scenario configuration: {scenario_path}")
        return 0

    scenarios = load_scenarios(scenario_path)
    runs_dir = Path(args.runs_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not runs_dir.is_dir():
        raise FileNotFoundError(f"Runs directory not found: {runs_dir}")

    engine = ContextualRiskEngine.from_environment(args.environment)
    predictions: list[dict[str, Any]] = []
    errors: list[str] = []

    for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
        run_info_path = run_dir / "run_info.json"
        wazuh_path = run_dir / "live_wazuh_events.json"
        zeek_path = run_dir / "live_zeek_conn.json"
        if not (run_info_path.exists() and wazuh_path.exists() and zeek_path.exists()):
            continue
        try:
            run_info = read_json(run_info_path)
            scenario_id = scenario_id_from_run(run_info, run_dir)
            scenario = scenarios.get(scenario_id)
            if scenario is None:
                errors.append(f"{run_dir.name}: unknown ScenarioID {scenario_id}")
                continue
            predictions.append(
                evaluate_run(
                    run_dir=run_dir,
                    scenario=scenario,
                    engine=engine,
                    output_root=output_dir,
                    padding=timedelta(seconds=max(args.time_padding_seconds, 0)),
                    allow_reverse=args.allow_reverse_flow,
                )
            )
        except Exception as exc:  # evaluation should report run failures explicitly
            errors.append(f"{run_dir.name}: {exc}")

    predictions.sort(key=lambda row: (row["ScenarioID"], row["RunID"]))
    write_csv(output_dir / "final_run_predictions.csv", predictions)

    binary_metrics = compute_binary_metrics(predictions)
    write_csv(output_dir / "binary_metrics.csv", binary_metrics)
    write_csv(output_dir / "binary_confusion_matrix.csv", compute_binary_confusion(predictions))

    multiclass_metrics, multiclass_matrix = compute_multiclass_metrics(predictions)
    write_csv(output_dir / "four_class_metrics.csv", multiclass_metrics)
    write_csv(output_dir / "multiclass_confusion_matrix.csv", multiclass_matrix)

    correlation_summary, correlation_details = correlation_outputs(predictions)
    write_csv(output_dir / "correlation_summary.csv", correlation_summary)
    write_csv(output_dir / "correlation_run_details.csv", correlation_details)

    validation_problems = validate_expected_runs(
        predictions,
        scenarios,
        args.expected_runs_per_scenario,
    )
    report = {
        "environment": args.environment,
        "runs_directory": str(runs_dir),
        "scenario_configuration": str(scenario_path),
        "total_runs_discovered": len(predictions),
        "accepted_runs": sum(1 for row in predictions if row["Accepted"]),
        "excluded_runs": sum(1 for row in predictions if not row["Accepted"]),
        "expected_total_runs": len(scenarios) * args.expected_runs_per_scenario,
        "validation_problems": validation_problems,
        "processing_errors": errors,
        "severity_only_mapping": {
            "0-4": "Legitimate",
            "5-7": "Low Suspicion",
            "8-11": "Suspicious",
            "12-15": "Likely Malicious",
        },
        "binary_mapping": {
            "Legitimate": "Negative",
            "Low Suspicion": "Negative",
            "Suspicious": "Positive",
            "Likely Malicious": "Positive",
        },
    }
    write_json(output_dir / "evaluation_validation.json", report)

    print(f"Runs discovered : {report['total_runs_discovered']}")
    print(f"Accepted runs   : {report['accepted_runs']}")
    print(f"Excluded runs   : {report['excluded_runs']}")
    print(f"Expected runs   : {report['expected_total_runs']}")
    print(f"Output directory: {output_dir}")

    if errors:
        print("\nProcessing errors:")
        for problem in errors:
            print(f"  - {problem}")
    if validation_problems:
        print("\nValidation problems:")
        for problem in validation_problems:
            print(f"  - {problem}")

    if (errors or validation_problems) and not args.allow_incomplete:
        print("\nEvaluation is incomplete. Fix the evidence or rerun with --allow-incomplete for diagnostic output only.")
        return 2

    print("\nChapter 6 evaluation outputs generated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())