#!/usr/bin/env python3
"""
Ghost Data Still Exists — deterministic, evidence-grounded deletion audit agent.

Run from repository root:
    python code/main.py
Optional:
    python code/main.py --dataset dataset --output output.csv
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
DIRECT_FIELDS = {
    "email", "owner_email", "customer_email", "contact_email", "full_name",
    "name", "phone", "email_hash", "email_sha256", "customer_name",
    "display_name", "subject_email", "recipient_email", "user_email",
    "requester_email", "requester_name"
}
ID_FIELDS = {
    "user_id", "customer_reference", "subject_reference", "owner_user_id",
    "customer_id", "subject_id", "requester_id"
}
RESOURCE_FIELDS = {"resource_id", "record_id", "id", "resource", "object_id"}
TIME_FIELDS = {"captured_at", "updated_at", "created_at", "event_time", "timestamp", "observed_at"}
FLOW_WORDS = ("flow", "connector", "sync", "import", "replication", "pipeline", "job")
BACKUP_WORDS = ("backup", "archive", "restore", "snapshot")
DELETION_WORDS = re.compile(
    r"\b(delete|deleted|deleting|deletion|erase|erased|erasing|erasure|"
    r"remove|removed|removing|removal|close|closed|closing|deactivate|"
    r"deactivation|purge|exclus[aã]o|supresi[oó]n|suppression|"
    r"eliminar|eliminaci[oó]n|supprimer|suppression|effacer)\b|"
    r"削除|アカウント.{0,12}削除",
    re.I,
)
NON_DELETE_WORDS = re.compile(
    r"\b(access request|request access|export my data|data portability|correct my|"
    r"rectify|update my details|marketing opt[- ]?out|unsubscribe|stop marketing|"
    r"opt out of marketing|consulta de acceso|acceso a mis datos)\b",
    re.I,
)

def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Required input not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def parse_time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        s = str(value).strip().replace("Z", "+00:00")
        out = dt.datetime.fromisoformat(s)
        if out.tzinfo is None:
            out = out.replace(tzinfo=dt.timezone.utc)
        return out.astimezone(dt.timezone.utc)
    except Exception:
        return None

def before_or_at(value: Any, cutoff: Any) -> bool:
    a, b = parse_time(value), parse_time(cutoff)
    return a is None or b is None or a <= b

def norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().casefold())

def norm_email(value: Any) -> str:
    return norm(value).strip("<> ,;\"'")

def is_truthy(value: Any) -> bool:
    return str(value).strip().casefold() in {"true", "1", "yes", "enabled", "active", "success", "allowed"}

def has_deletion_intent(text: str) -> bool:
    t = text or ""
    if NON_DELETE_WORDS.search(t) and not DELETION_WORDS.search(t):
        return False
    return bool(
        DELETION_WORDS.search(t)
        or re.search(r"\b(?:account|profile|records?)\b.{0,60}\b(?:gone|removed|erased|deleted|closed)\b", t, re.I)
    )

def flatten_dicts(obj: Any, parents: dict[str, Any] | None = None) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    """Yield each dict with inherited context from parent snapshot/collection objects."""
    parents = parents or {}
    if isinstance(obj, dict):
        local = dict(parents)
        for k in ("data_store", "system_id", "system", "collection", "table", "captured_at",
                  "snapshot_at", "event_time", "data_category", "category", "resource_type"):
            if k in obj and not isinstance(obj[k], (dict, list)):
                local[k] = obj[k]
        yield obj, local
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                child_context = dict(local)
                if k.casefold() in {
                    "account_service", "profile_service", "search_service", "cache_service",
                    "support_platform", "export_service", "analytics_platform", "marketing_service",
                    "email_delivery_service", "security_service", "backup_service", "archive_service",
                    "integration_service", "legal_service",
                }:
                    child_context["system_id"] = k
                elif k.casefold() in {
                    "profile_lookups", "profiles", "search_documents", "cache_entries",
                    "support_messages", "support_attachments", "exports", "export_jobs",
                    "analytics_profiles", "audit_records", "backup_records", "data_flows",
                }:
                    child_context["collection"] = k
                yield from flatten_dicts(v, child_context)
    elif isinstance(obj, list):
        for v in obj:
            yield from flatten_dicts(v, parents)

def maybe_decode_text(path: Path) -> str:
    suffix = path.suffix.casefold()
    try:
        if suffix in {".json", ".txt", ".log", ".csv", ".md", ".sql", ".xml", ".yaml", ".yml"}:
            return path.read_text(encoding="utf-8", errors="replace")
        if suffix == ".pdf":
            try:
                from pypdf import PdfReader
            except ImportError:
                print(f"WARNING: PDF evidence skipped; install pypdf to read {path}", file=sys.stderr)
                return ""
            try:
                return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
            except Exception as exc:
                raise RuntimeError(f"Could not extract PDF evidence from {path}: {exc}") from exc
        if suffix in {".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff"}:
            try:
                from PIL import Image
                import pytesseract
            except ImportError:
                print(
                    f"WARNING: image evidence skipped; install Pillow, pytesseract, "
                    f"and Tesseract to read {path}",
                    file=sys.stderr,
                )
                return ""
            try:
                return pytesseract.image_to_string(Image.open(path))
            except Exception as exc:
                print(f"WARNING: image OCR failed for {path}: {exc}", file=sys.stderr)
                return ""
    except OSError as exc:
        raise RuntimeError(f"Could not read evidence file {path}: {exc}") from exc
    return ""

def infer_system(context: dict[str, Any], record: dict[str, Any], path: str = "") -> str:
    explicit = (context.get("system_id") or context.get("data_store") or
                context.get("system") or record.get("system_id") or record.get("data_store"))
    if explicit:
        s = str(explicit).strip().casefold()
        aliases = {
            "customer_profiles": "account_service",
            "customer_profile": "account_service",
            "customer_profiles_primary": "account_service",
            "customer_profiles_failover_replica": "account_service",
            "customer_profiles_reporting_replica": "account_service",
            "customer_search_documents": "search_service",
            "search_index": "search_service",
            "connector_configurations": "integration_service",
            "customer_export_jobs": "export_service",
            "backup_catalog": "backup_service",
            "security_audit_ledger": "security_service",
        }
        return aliases.get(s, s)
    s = (str(context.get("collection", "")) + " " + str(context.get("table", "")) + " " + path).casefold()
    for key, val in [
        ("account", "account_service"), ("profile", "profile_service"), ("search", "search_service"),
        ("cache", "cache_service"), ("support", "support_platform"), ("attachment", "support_platform"),
        ("export", "export_service"), ("analytics", "analytics_platform"), ("telemetry", "analytics_platform"),
        ("marketing", "marketing_service"), ("email_delivery", "email_delivery_service"),
        ("security", "security_service"), ("legal", "legal_service"), ("backup", "backup_service"),
        ("archive", "archive_service"), ("connector", "integration_service"), ("integration", "integration_service"),
    ]:
        if key in s:
            return val
    return "unknown_system"

def infer_category(context: dict[str, Any], record: dict[str, Any], system: str) -> str:
    resource_id = str(record.get("resource_id", "")).casefold()
    if resource_id.startswith("data_flow_"):
        return "ACTIVE_DATA_FLOW"
    raw = " ".join(str(context.get(k, "")) for k in ("data_category", "category", "collection", "table", "resource_type"))
    raw += " " + " ".join(str(record.get(k, "")) for k in (
        "data_category", "category", "record_type", "resource_type", "resource_id"
    ))
    raw = raw.casefold()
    checks = [
        (("tombstone",), "ACCOUNT_TOMBSTONE"),
        (("legal_hold", "legal hold", "legal_retention", "retention_register"), "LEGAL_HOLD_RECORD"),
        (("security_audit", "audit_ledger", "audit_record", "security event"), "SECURITY_AUDIT_LOG"),
        (("email_delivery", "delivery_log", "mail_log"), "EMAIL_DELIVERY_LOG"),
        (("support_attachment", "attachment"), "SUPPORT_ATTACHMENT"),
        (("support_message", "conversation", "support_case", "ticket"), "SUPPORT_MESSAGE"),
        (("analytics", "customer_analytics"), "ANALYTICS_PROFILE"),
        (("telemetry", "product_event"), "PRODUCT_TELEMETRY"),
        (("search", "index_document"), "SEARCH_INDEX_ENTRY"),
        (("cache",), "CACHE_ENTRY"),
        (("export",), "USER_EXPORT"),
        (("marketing",), "MARKETING_PROFILE"),
        (("backup", "archive", "snapshot"), "BACKUP_ARCHIVE"),
        (("secondary_identifier", "identifier_map"), "SECONDARY_IDENTIFIER"),
        (("data_flow", "connector", "integration"), "ACTIVE_DATA_FLOW"),
        (("customer_profile", "user_profile", "account"), "USER_PROFILE"),
    ]
    for terms, category in checks:
        if any(t in raw for t in terms):
            return category
    sys_map = {
        "account_service": "USER_PROFILE", "profile_service": "USER_PROFILE",
        "search_service": "SEARCH_INDEX_ENTRY", "cache_service": "CACHE_ENTRY",
        "support_platform": "SUPPORT_MESSAGE", "export_service": "USER_EXPORT",
        "analytics_platform": "ANALYTICS_PROFILE", "marketing_service": "MARKETING_PROFILE",
        "email_delivery_service": "EMAIL_DELIVERY_LOG", "security_service": "SECURITY_AUDIT_LOG",
        "backup_service": "BACKUP_ARCHIVE", "archive_service": "BACKUP_ARCHIVE",
        "integration_service": "SECONDARY_IDENTIFIER",
    }
    return sys_map.get(system, "USER_PROFILE")

def action_for(category: str, record: dict[str, Any], cutoff: Any) -> str:
    if category == "SECURITY_AUDIT_LOG":
        retention_end = first_value(record, {"retain_until", "retention_until", "retention_end"})
        if retention_end and parse_time(retention_end) and parse_time(cutoff):
            return "RETAIN" if parse_time(retention_end) >= parse_time(cutoff) else "DELETE"
        return "RETAIN"
    if category == "LEGAL_HOLD_RECORD":
        return "RETAIN" if is_truthy(record.get("active", record.get("legal_hold_active", True))) else "DELETE"
    if category == "BACKUP_ARCHIVE":
        return "RETAIN"
    if category == "ACTIVE_DATA_FLOW":
        return "FLOW"
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        return "ANONYMIZE"
    if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}:
        return "REDACT"
    return "DELETE"


def policy_action(category: str, record: dict[str, Any], cutoff: Any,
                  rules: list[dict[str, str]]) -> str:
    action = action_for(category, record, cutoff)
    configured = next(
        (rule.get("required_action", "").upper() for rule in rules
         if rule.get("data_category", "").upper() == category),
        "",
    )
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE"}:
        return action
    return configured or action

def record_identifiers(record: dict[str, Any]) -> set[str]:
    vals = set()
    for k, v in record.items():
        if isinstance(v, (dict, list)) or v is None:
            continue
        if k.casefold() in DIRECT_FIELDS or k.casefold() in ID_FIELDS or k.casefold() in {
            "email", "user_id", "customer_reference", "subject_reference", "email_hash", "phone", "full_name", "name"
        }:
            vals.add(norm(v))
    return vals

def object_contains_alias(record: dict[str, Any], aliases: set[str]) -> bool:
    ids = record_identifiers(record)
    return bool(ids.intersection(aliases))

def extract_sql_records(text: str, path: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    records: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def hydrate_json_payload(record: dict[str, Any]) -> dict[str, Any]:
        for key, value in record.items():
            if str(key).casefold() not in {
                "record_json", "payload_json", "document_json", "data_json", "payload", "document"
            } or not isinstance(value, str):
                continue
            try:
                payload = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                hydrated = dict(payload)
                hydrated.update(record)
                return hydrated
        return record

    db = sqlite3.connect(":memory:")
    try:
        db.executescript(text)
        names = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in names:
            cur = db.execute(f'SELECT * FROM "{table}"')
            cols = [d[0] for d in cur.description or []]
            for row in cur.fetchall():
                rec = hydrate_json_payload(dict(zip(cols, row)))
                records.append((rec, {
                    "table": table,
                    "data_store": infer_system({"table": table}, rec, path),
                    "collection": table,
                }))
    except Exception:
        # SQL files may contain multiple independent fragments; fallback parses INSERT statements.
        pattern = re.compile(r'INSERT\s+INTO\s+["`\[]?([\w.-]+)["`\]]?\s*(?:\(([^)]*)\))?\s*VALUES\s*\((.*?)\)\s*;', re.I | re.S)
        for m in pattern.finditer(text):
            table, columns, values = m.groups()
            def split_sql_values(s: str) -> list[str]:
                return re.findall(r"""'(?:''|[^'])*'|"(?:\\"|[^"])*"|\bNULL\b|[^,]+""", s)
            vals = split_sql_values(values)
            vals = [v.strip().strip("'\"").replace("''", "'") for v in vals]
            cols = [c.strip().strip('"`[]') for c in columns.split(",")] if columns else [f"col_{i}" for i in range(len(vals))]
            rec = hydrate_json_payload(dict(zip(cols, vals)))
            records.append((rec, {
                "table": table,
                "collection": table,
                "data_store": infer_system({"table": table}, rec, path),
            }))
    finally:
        db.close()
    return records

def load_evidence(dataset: Path) -> list[dict[str, Any]]:
    manifest = read_csv(dataset / "evidence_files.csv")
    evidence = []
    for item in manifest:
        file_id = item.get("file_id", "")
        rel = item.get("file_path", "")
        path = dataset / rel
        if not path.exists():
            continue
        raw = maybe_decode_text(path)
        parsed = None
        if path.suffix.casefold() == ".json":
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = None
        records: list[tuple[dict[str, Any], dict[str, Any]]] = []
        if parsed is not None:
            for record, context in flatten_dicts(parsed):
                if not first_value(record, RESOURCE_FIELDS) and any(
                    isinstance(value, (dict, list)) for value in record.values()
                ):
                    continue
                records.append((record, context))
        elif path.suffix.casefold() == ".sql":
            records.extend(extract_sql_records(raw, rel))
        elif path.suffix.casefold() == ".pdf":
            if "legal_retention" in rel.casefold() or "retention_register" in rel.casefold():
                for line_no, line in enumerate(raw.splitlines(), 1):
                    if re.search(r"\buser_[\w-]+\b", line, re.I) and first_resource_id(line):
                        record = parse_text_record(line)
                        record["resource_id"] = first_resource_id(line)
                        records.append((record, {
                            "data_store": infer_system({}, {}, rel),
                            "collection": rel,
                            "line_no": line_no,
                        }))
            else:
                resource = first_resource_id(raw)
                if resource:
                    records.append(({"resource_id": resource, "_text": raw}, {
                        "data_store": infer_system({}, {}, rel), "collection": rel
                    }))
        else:
            parsed_lines: list[tuple[int, dict[str, Any]]] = []
            identifiers_by_trace: dict[str, dict[str, Any]] = defaultdict(dict)
            for line_no, line in enumerate(raw.splitlines(), 1):
                record = parse_text_record(line)
                trace_id = str(record.get("trace_id", "")).strip()
                if trace_id:
                    for key in (
                        "email", "customer_reference", "subject_reference", "user_id",
                        "email_hash", "phone", "name",
                    ):
                        value = record.get(key)
                        if value and str(value).casefold() not in {"null", "none"}:
                            identifiers_by_trace[trace_id][key] = value
                resource = first_value(record, RESOURCE_FIELDS) or first_resource_id(line)
                if resource:
                    record["resource_id"] = resource
                    parsed_lines.append((line_no, record))
            for line_no, record in parsed_lines:
                inherited = identifiers_by_trace.get(str(record.get("trace_id", "")), {})
                for key, value in inherited.items():
                    record.setdefault(key, value)
                records.append((record, {
                    "data_store": record.get("system_id") or infer_system({}, {}, rel),
                    "collection": rel, "line_no": line_no
                }))
        for rec, ctx in records:
            ctx = dict(ctx)
            ctx.setdefault("file_path", rel)
            ctx.setdefault("manifest_captured_at", item.get("captured_at", ""))
            ctx.setdefault("file_id", file_id)
            ctx.setdefault("record_time", first_value(rec, TIME_FIELDS) or ctx.get("captured_at") or item.get("captured_at"))
            ctx.setdefault("system_id", infer_system(ctx, rec, rel))
            ctx.setdefault("category", infer_category(ctx, rec, ctx["system_id"]))
            resource = first_value(rec, RESOURCE_FIELDS)
            if not resource:
                resource = first_resource_id(json.dumps(rec, ensure_ascii=False))
            if not resource:
                continue
            evidence.append({
                "file_id": file_id, "file_path": rel, "captured_at": item.get("captured_at", ""),
                "record_time": ctx.get("record_time"), "system_id": str(ctx["system_id"]),
                "resource_id": str(resource), "category": str(ctx["category"]),
                "record": rec, "context": ctx,
                "raw": json.dumps(rec, ensure_ascii=False, default=str),
                "match_text": str(rec.get("_line", rec.get("_text", ""))),
            })
    return evidence

def first_value(record: dict[str, Any], keys: set[str]) -> Any:
    for k, v in record.items():
        if str(k).casefold() in keys and v not in (None, "") and not isinstance(v, (dict, list)):
            return v
    return None

def first_resource_id(text: str) -> str | None:
    m = re.search(
        r"\b(account|search|support|export|analytics|cache|backup|audit_record|"
        r"email_delivery|data_flow|marketing|telemetry|attachment|tombstone|"
        r"profile)_\d+\b|\bORD-[A-Z0-9-]+\b",
        text,
        re.I,
    )
    return m.group(0) if m else None


def parse_text_record(line: str) -> dict[str, Any]:
    record: dict[str, Any] = {"_line": line}
    parts = [part.strip().lstrip("-").strip() for part in line.split("|")]
    timestamp_match = re.match(r"\s*-?\s*(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)", line)
    if timestamp_match:
        record["timestamp"] = timestamp_match.group(1)

    for match in re.finditer(
        r"""(?<![\w.-])([A-Za-z_][\w.-]*)=("([^"]*)"|'([^']*)'|[^\s]+)""",
        line,
    ):
        key = match.group(1).casefold()
        value = next((group for group in match.groups()[2:] if group is not None), match.group(2))
        record[key] = value

    if len(parts) >= 5 and re.fullmatch(r"\d{4}-\d{2}-\d{2}T.+", parts[0]):
        record.update({
            "timestamp": parts[0],
            "system_id": parts[1],
            "resource_id": parts[2],
            "data_category": parts[3],
            "status": parts[4],
        })
        if len(parts) > 5:
            subject = parts[5]
            if "@" in subject:
                record["email"] = subject
            elif re.fullmatch(r"user_[\w-]+", subject, re.I):
                record["customer_reference"] = subject
            elif subject.casefold() not in {"no direct identifier", "null", "none"}:
                record["subject_reference"] = subject

    if "service" in record and "system_id" not in record:
        record["system_id"] = record["service"]
    if "data_category" not in record:
        for key in ("category", "record_type", "resource_type"):
            if key in record:
                record["data_category"] = record[key]
                break
    for key in (
        "subject_email", "customer_email", "requester_email", "owner_email",
        "user_email", "subject_key",
    ):
        if record.get(key):
            record.setdefault("email", record[key])
    correlation = record.get("correlation_key", "")
    if correlation and re.fullmatch(r"[a-f0-9]{64}", correlation, re.I):
        record.setdefault("email_hash", correlation)
    elif correlation and "@" in correlation:
        record.setdefault("email", correlation)
    elif correlation and re.fullmatch(r"user_[\w-]+", correlation, re.I):
        record.setdefault("customer_reference", correlation)
    lookup = record.get("lookup_key")
    if lookup and lookup.casefold() not in {"null", "none"}:
        if "@" in lookup:
            record["email"] = lookup
        elif re.fullmatch(r"user_[\w-]+", lookup, re.I):
            record["customer_reference"] = lookup

    if "status" not in record:
        for key in ("state", "result", "reported_result", "http_status"):
            if key in record:
                record["status"] = record[key]
                break
    if str(record.get("http_status", "")) == "404" or str(record.get("rows", "")) == "0":
        record["status"] = "NOT_FOUND"
    subject = re.search(r"\buser_[\w-]+\b", line, re.I)
    if subject:
        record.setdefault("customer_reference", subject.group(0))
    retained_until = re.search(
        r"\bretain(?:ed)?\s+until\s+(\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})\b",
        line,
        re.I,
    )
    if retained_until:
        try:
            record["retention_until"] = dt.datetime.strptime(
                retained_until.group(1), "%d %B %Y"
            ).replace(tzinfo=dt.timezone.utc).isoformat()
        except ValueError:
            record["retention_until"] = dt.datetime.strptime(
                retained_until.group(1), "%d %b %Y"
            ).replace(tzinfo=dt.timezone.utc).isoformat()
    return record

def build_identity_index(identities: list[dict[str, str]], audit: list[dict[str, str]]) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
    by_user: dict[str, dict[str, Any]] = {}
    alias_to_user: dict[str, str] = {}
    aliases_by_user: dict[str, set[str]] = defaultdict(set)
    for row in identities:
        uid = row.get("user_id", "")
        if not uid:
            continue
        by_user[uid] = row
        for k in ("name", "email", "phone", "email_hash"):
            if row.get(k):
                val = norm_email(row[k]) if k == "email" else norm(row[k])
                aliases_by_user[uid].add(val)
                alias_to_user[val] = uid
    for row in audit:
        uid = row.get("user_id", "")
        if not uid:
            continue
        field = row.get("field_name", "").casefold()
        for k in ("old_value", "new_value"):
            val = row.get(k, "")
            if val:
                val = norm_email(val) if field == "email" else norm(val)
                aliases_by_user[uid].add(val)
                # Most recent audit entry is not guaranteed to be last; preserve mapping only if unambiguous.
                alias_to_user.setdefault(val, uid)
    return by_user, aliases_by_user

def resolve_user(request: dict[str, str], by_user: dict[str, dict[str, Any]],
                 aliases_by_user: dict[str, set[str]], audit: list[dict[str, str]]) -> str | None:
    email = norm_email(request.get("email"))
    direct = [uid for uid, row in by_user.items() if norm_email(row.get("email")) == email]
    if direct:
        return direct[0]
    matches = [uid for uid, aliases in aliases_by_user.items() if email in aliases]
    if len(matches) == 1:
        return matches[0]
    # Email changes may have multiple events; resolve old email by audit log.
    matches = [r.get("user_id") for r in audit
               if r.get("field_name", "").casefold() == "email" and
               norm_email(r.get("old_value")) == email]
    matches = list(dict.fromkeys(m for m in matches if m))
    return matches[0] if len(matches) == 1 else None

def evidence_matches(ev: dict[str, Any], aliases: set[str], uid: str) -> bool:
    rec = ev["record"]
    vals = record_identifiers(rec)
    if norm(uid) in vals:
        return True
    text = norm(ev.get("match_text") or ev["raw"])
    return any(
        alias in vals
        or bool(re.search(
            r"(?<![\w@.+-])" + re.escape(alias) + r"(?![\w@.+-])",
            text,
        ))
        for alias in aliases
        if alias
    )

def direct_pii_present(record: dict[str, Any], aliases: set[str]) -> bool:
    for k, v in record.items():
        if isinstance(v, (dict, list)) or v in (None, ""):
            continue
        key = str(k).casefold()
        if key in DIRECT_FIELDS:
            val = norm_email(v) if "email" in key else norm(v)
            if val in aliases or val not in {"", "null", "none", "redacted", "anonymous", "anonymized"}:
                return True
    return False

def state_for(ev: dict[str, Any], category: str, action: str) -> str:
    rec, ctx = ev["record"], ev["context"]
    vals = {str(k).casefold(): str(v).casefold() for k, v in rec.items() if not isinstance(v, (dict, list))}
    joined = " ".join(vals.values()).casefold()
    if category == "ACCOUNT_TOMBSTONE":
        return "PRESENT" if direct_pii_present(rec, set()) else "REDACTED"
    if category == "BACKUP_ARCHIVE":
        restore = vals.get("restore_allowed") or vals.get("restore_enabled") or vals.get("can_restore")
        if restore is not None:
            return "ACTIVE" if is_truthy(restore) else "BLOCKED"
        if any(x in joined for x in ("restore blocked", "restore disabled", "cannot restore", "not restorable", "blocked")):
            return "BLOCKED"
        return "ACTIVE"
    if category == "ACTIVE_DATA_FLOW":
        status = " ".join(vals.get(k, "") for k in ("enabled", "is_enabled", "active", "status", "state", "result"))
        if any(x in status for x in ("disabled", "inactive", "stopped", "false", "0")):
            return "DISABLED"
        if any(x in status for x in ("active", "enabled", "true", "running")):
            return "ACTIVE"
        return "UNKNOWN"
    status_fields = [
        "enabled", "is_enabled", "active", "status", "state", "result",
        "reported_result", "status_code", "http_status",
    ]
    if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER"}:
        status_fields.append("account_status")
    statuses = " ".join(vals.get(key, "") for key in status_fields)
    if any(x in statuses for x in ("not_found", "not found", "missing", "no rows", "404", "deleted", "absent", "removed")):
        return "ABSENT"
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if direct_pii_present(rec, set()):
            return "PRESENT"
        return "ANONYMIZED"
    if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
        if direct_pii_present(rec, set()):
            return "PRESENT"
        if any(x in statuses for x in ("redacted", "redact")):
            return "REDACTED"
        return "PRESENT" if action == "DELETE" else "REDACTED"
    if any(x in statuses for x in ("redacted", "redact")):
        return "REDACTED"
    if any(x in statuses for x in ("anonymized", "anonymised", "anonymous")):
        return "ANONYMIZED"
    if any(x in statuses for x in ("identifiable", "present", "found", "active", "enabled", "true")):
        return "PRESENT"
    if category == "LEGAL_HOLD_RECORD":
        until = first_value(rec, {"retain_until", "retention_until", "retention_end"})
        if until and parse_time(until) and parse_time(ctx.get("manifest_captured_at")):
            return "PRESENT" if parse_time(until) >= parse_time(ctx["manifest_captured_at"]) else "ABSENT"
    return "PRESENT"

def step(phase: str, system: str, resource: str, operation: str, state: str, evidence: str = "") -> dict[str, Any]:
    return {
        "step_no": 0, "phase": phase, "system_id": system, "resource_id": resource,
        "operation": operation, "state": state, "evidence_id": evidence or ""
    }

def sort_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Phase then operation as required by the contract, then system/resource.
    steps.sort(key=lambda x: (
        PHASE_ORDER.get(x["phase"], 99),
        OP_ORDER.get(x["operation"], 99),
        x["system_id"], x["resource_id"]
    ))
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    return steps

def choose_violation_operation(category: str, action: str, record: dict[str, Any],
                               aliases: set[str], state: str) -> tuple[str, str] | None:
    if action == "DELETE":
        if state == "ABSENT":
            return None
        return "REPORT_REMAINING_RECORD", "PRESENT"
    if action == "REDACT":
        if state != "ABSENT" and (direct_pii_present(record, aliases) or state == "PRESENT"):
            return "REPORT_EXPOSED_PII", "PRESENT"
        return None
    if action == "ANONYMIZE":
        if state != "ABSENT" and (
            direct_pii_present(record, aliases) or state == "PRESENT" or any(
            str(v).casefold() in {a.casefold() for a in aliases}
            for k, v in record.items() if str(k).casefold() in ID_FIELDS and v not in (None, "")
            )
        ):
            return "REPORT_EXPOSED_PII", "PRESENT"
        return None
    return None

def operation_for_action(action: str) -> tuple[str, str, str]:
    if action == "DELETE": return "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT"
    if action == "REDACT": return "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED"
    if action == "ANONYMIZE": return "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"
    return "", "", ""

def make_case(request: dict[str, str], by_user: dict[str, dict[str, Any]],
              aliases_by_user: dict[str, set[str]], audit: list[dict[str, str]],
              evidence: list[dict[str, Any]], activities: list[dict[str, str]],
              rules: list[dict[str, str]]) -> tuple[str, list[dict[str, Any]]]:
    if not has_deletion_intent(request.get("request_text", "")):
        return "NOT_APPLICABLE", []
    uid = resolve_user(request, by_user, aliases_by_user, audit)
    if not uid:
        # Do not mark complete if identity cannot be resolved from supplied evidence.
        return "INCOMPLETE", []
    cutoff = request.get("audit_at", "")
    aliases = set(aliases_by_user.get(uid, set()))
    aliases.add(norm(uid))
    aliases = {a for a in aliases if a}
    valid_evidence = [e for e in evidence if before_or_at(e.get("captured_at"), cutoff)
                      and before_or_at(e.get("record_time"), cutoff)]
    direct_matches = [e for e in valid_evidence if evidence_matches(e, aliases, uid)]
    matched_resources = {
        (e["system_id"], e["resource_id"])
        for e in direct_matches
    }
    matches = [
        e for e in valid_evidence
        if (e["system_id"], e["resource_id"]) in matched_resources
    ]
    # Collapse repeated copies of the same logical record to the strongest/latest observation.
    # Preserve separate systems and resource IDs.
    by_resource: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in matches:
        key = (ev["system_id"], ev["resource_id"])
        old = by_resource.get(key)

        def observation_rank(item: dict[str, Any]) -> tuple[dt.datetime, int, int, int]:
            record = item["record"]
            observed_at = parse_time(item.get("record_time")) or parse_time(item.get("captured_at"))
            observed_at = observed_at or dt.datetime.min.replace(tzinfo=dt.timezone.utc)
            has_result = any(
                str(record.get(k, "")).strip()
                for k in ("status", "state", "result", "reported_result", "account_status")
            )
            event_completed = "completed" in str(record.get("event", "")).casefold()
            return observed_at, int(has_result), int(event_completed), len(record)

        if old is None or observation_rank(ev) > observation_rank(old):
            by_resource[key] = ev
    matches = list(by_resource.values())

    flows: list[dict[str, Any]] = []
    violations: list[tuple[dict[str, Any], str, str, tuple[str, str]]] = []
    compliant: list[tuple[dict[str, Any], str, str]] = []
    for ev in matches:
        rec = ev["record"]
        category = ev["category"]
        action = policy_action(category, rec, cutoff, rules)
        state = state_for(ev, category, action)
        if category == "ACTIVE_DATA_FLOW":
            if state == "ACTIVE":
                flows.append(ev)
            else:
                compliant.append((ev, action, state))
            continue
        if category == "BACKUP_ARCHIVE":
            if state == "ACTIVE":
                flows.append(ev)
            else:
                compliant.append((ev, action, state))
            continue
        violation = choose_violation_operation(category, action, rec, aliases, state)
        if violation:
            violations.append((ev, category, action, violation))
        else:
            compliant.append((ev, action, state))

    # Include relevant system_activity entries that can recreate a matching resource.
    # These are only used when the event mentions an identified resource or identity.
    for a in activities:
        if not before_or_at(a.get("event_time"), cutoff):
            continue
        details = norm(a.get("details", ""))
        resource = a.get("resource_id", "")
        if any(alias and re.search(
            r"(?<![\w@.+-])" + re.escape(alias) + r"(?![\w@.+-])",
            details,
        ) for alias in aliases):
            event_type = (a.get("event_type") or "").upper()
            if any(x in event_type for x in ("SYNC", "IMPORT", "RESTORE", "INDEX", "EXPORT")):
                flows.append({
                    "system_id": a.get("target_system") or a.get("source_system") or "unknown_system",
                    "resource_id": resource or "unknown_resource", "file_id": a.get("activity_id", ""),
                    "category": "ACTIVE_DATA_FLOW", "record": a, "context": {},
                    "raw": json.dumps(a), "captured_at": a.get("event_time")
                })

    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []

    for ev, category, action, violation in violations:
        op, state = violation
        findings.append(step("FINDING", ev["system_id"], ev["resource_id"], op, state, ev["file_id"]))
        rem_op, rem_state, ver_op = operation_for_action(action)
        if rem_op:
            remediations.append(step("REMEDIATION", ev["system_id"], ev["resource_id"], rem_op, rem_state, ""))
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"], ver_op, rem_state, ""))

    for ev in flows:
        is_backup = ev.get("category") == "BACKUP_ARCHIVE"
        findings.append(step("FINDING", ev["system_id"], ev["resource_id"],
                             "REPORT_RESTORE_RISK" if is_backup else "REPORT_ACTIVE_DATA_FLOW",
                             "ACTIVE", ev.get("file_id", "")))
        if is_backup:
            remediations.append(step("REMEDIATION", ev["system_id"], ev["resource_id"], "BLOCK_RESTORE", "BLOCKED", ""))
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"], "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
        else:
            remediations.append(step("REMEDIATION", ev["system_id"], ev["resource_id"], "DISABLE_DATA_FLOW", "DISABLED", ""))
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"], "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))

    # For every incomplete case, require verification of the primary account absence.
    for ev, action, state in compliant:
        if action == "RETAIN" and ev["category"] == "BACKUP_ARCHIVE":
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"],
                                      "VERIFY_RESTORE_BLOCKED", "BLOCKED", ev["file_id"]))
        elif action == "RETAIN":
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"],
                                      "VERIFY_RECORD_PRESENT", "PRESENT", ev["file_id"]))
        elif action == "ANONYMIZE":
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"],
                                      "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ev["file_id"]))
        elif action == "REDACT":
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"],
                                      "VERIFY_RECORD_REDACTED", "REDACTED", ev["file_id"]))
        elif action == "FLOW":
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"],
                                      "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ev["file_id"]))
        elif state == "ABSENT":
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"],
                                      "VERIFY_RECORD_ABSENT", "ABSENT", ev["file_id"]))
        else:
            verifications.append(step("VERIFICATION", ev["system_id"], ev["resource_id"],
                                      "VERIFY_RECORD_PRESENT", "PRESENT", ev["file_id"]))
    incomplete = bool(violations or flows)
    if incomplete:
        status = "INCOMPLETE"
        return status, sort_steps(findings + remediations + verifications)
    if not verifications:
        # Lack of evidence is not proof of deletion; avoid a false COMPLETE.
        return "INCOMPLETE", []
    return "COMPLETE", sort_steps(verifications)

def validate_csv_schema(path: Path, required: set[str]) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Required CSV file not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        columns = csv.DictReader(handle).fieldnames
    if columns is None:
        raise ValueError(f"CSV file has no header: {path}")
    missing = required - set(columns)
    if missing:
        raise ValueError(f"Incompatible CSV schema in {path}; missing columns: {', '.join(sorted(missing))}")


def validate_output(requests: list[dict[str, str]],
                    output_rows: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    request_ids = [row.get("case_id", "") for row in requests]
    output_ids = [row.get("case_id", "") for row in output_rows]
    if any(not case_id for case_id in request_ids):
        errors.append("input contains an empty case_id")
    if len(set(request_ids)) != len(request_ids):
        errors.append("input contains duplicate case_id values")
    if len(set(output_ids)) != len(output_ids):
        errors.append("output contains duplicate case_id values")
    if len(output_rows) != len(requests):
        errors.append(f"row count mismatch: {len(output_rows)} != {len(requests)}")
    if set(request_ids) != set(output_ids):
        missing = sorted(set(request_ids) - set(output_ids))
        unexpected = sorted(set(output_ids) - set(request_ids))
        if missing:
            errors.append(f"output is missing case_ids: {', '.join(missing[:10])}")
        if unexpected:
            errors.append(f"output contains unexpected case_ids: {', '.join(unexpected[:10])}")

    allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    allowed_states = {"ACTIVE", "ABSENT", "PRESENT", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"}
    step_fields = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
    for row in output_rows:
        case_id = row.get("case_id", "<empty>")
        if row.get("deletion_status") not in allowed_statuses:
            errors.append(f"{case_id}: invalid deletion_status {row.get('deletion_status')!r}")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except (TypeError, json.JSONDecodeError) as exc:
            errors.append(f"{case_id}: invalid steps_json: {exc}")
            continue
        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json is not an array")
            continue
        if row.get("deletion_status") == "NOT_APPLICABLE" and steps:
            errors.append(f"{case_id}: NOT_APPLICABLE must use []")
        for index, item in enumerate(steps, 1):
            if not isinstance(item, dict):
                errors.append(f"{case_id}: step {index} is not an object")
                continue
            if set(item) != step_fields:
                errors.append(f"{case_id}: step {index} does not have the required fields")
                continue
            if item["step_no"] != index:
                errors.append(f"{case_id}: step numbers are not consecutive")
            if item["phase"] not in PHASE_ORDER:
                errors.append(f"{case_id}: step {index} has invalid phase {item['phase']!r}")
            if item["operation"] not in OP_ORDER:
                errors.append(f"{case_id}: step {index} has invalid operation {item['operation']!r}")
            if item["state"] not in allowed_states:
                errors.append(f"{case_id}: step {index} has invalid state {item['state']!r}")
            for field in ("system_id", "resource_id", "evidence_id"):
                if not isinstance(item[field], str):
                    errors.append(f"{case_id}: step {index} field {field} must be a string")
        if steps and all(isinstance(item, dict) and set(item) == step_fields for item in steps):
            ordered = sorted(steps, key=lambda item: (
                PHASE_ORDER.get(item["phase"], 99),
                OP_ORDER.get(item["operation"], 99),
                item["system_id"],
                item["resource_id"],
            ))
            if steps != ordered:
                errors.append(f"{case_id}: steps are not in required phase/operation order")
    return errors


def evaluate_sample(dataset: Path, output_rows: list[dict[str, str]]) -> str:
    sample_requests_path = dataset / "sample_deletion_requests.csv"
    sample_output_path = dataset / "sample_output.csv"
    validate_csv_schema(sample_requests_path, {
        "case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"
    })
    validate_csv_schema(sample_output_path, {"case_id", "deletion_status", "steps_json"})
    sample_requests = read_csv(sample_requests_path)
    gold_rows = read_csv(sample_output_path)
    sample_ids = [row.get("case_id", "") for row in sample_requests]
    gold_ids = [row.get("case_id", "") for row in gold_rows]
    if len(set(sample_ids)) != len(sample_ids) or len(set(gold_ids)) != len(gold_ids):
        raise ValueError("Public sample files contain duplicate case_id values")
    if set(sample_ids) != set(gold_ids):
        raise ValueError("sample_deletion_requests.csv and sample_output.csv have different case_id sets")
    if any(not row.get("case_id") for row in gold_rows):
        raise ValueError("sample_output.csv contains an empty case_id")
    if any(row.get("deletion_status") not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"} for row in gold_rows):
        raise ValueError("sample_output.csv contains an invalid deletion_status")

    field_names = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
    gold: dict[str, tuple[str, list[dict[str, Any]]]] = {}
    for row in gold_rows:
        try:
            steps = json.loads(row["steps_json"])
        except (KeyError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid steps_json in sample_output.csv for {row.get('case_id')}: {exc}") from exc
        if not isinstance(steps, list) or any(
            not isinstance(item, dict) or set(item) != set(field_names) for item in steps
        ):
            raise ValueError(f"Incompatible step schema in sample_output.csv for {row['case_id']}")
        gold[row["case_id"]] = (row["deletion_status"], steps)

    predictions: dict[str, tuple[str, list[dict[str, Any]]]] = {}
    for row in output_rows:
        case_id = row.get("case_id", "")
        try:
            steps = json.loads(row["steps_json"])
        except (KeyError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid prediction steps_json for {case_id}: {exc}") from exc
        if not isinstance(steps, list):
            raise ValueError(f"Prediction steps_json for {case_id} is not an array")
        predictions[case_id] = (row.get("deletion_status", ""), steps)

    overlap = sorted(set(gold) & set(predictions))
    if not overlap:
        return (
            f"Public sample rows compared: 0 of {len(gold)}\n"
            "Sample evaluation: NOT RUN (no matching case_id values in this output; "
            "use --requests sample_deletion_requests.csv to evaluate the public sample)"
        )

    status_ok = exact_steps = sequence_ok = fields_ok = fields_total = 0
    for case_id in overlap:
        gold_status, gold_steps = gold[case_id]
        predicted_status, predicted_steps = predictions[case_id]
        status_ok += gold_status == predicted_status
        exact_steps += gold_steps == predicted_steps
        sequence_ok += len(gold_steps) == len(predicted_steps)
        for index in range(max(len(gold_steps), len(predicted_steps))):
            for field in field_names:
                fields_total += 1
                fields_ok += (
                    index < len(gold_steps)
                    and index < len(predicted_steps)
                    and gold_steps[index].get(field) == predicted_steps[index].get(field)
                )
    percentage = lambda numerator, denominator: (
        f"{numerator}/{denominator} ({numerator / denominator:.1%})" if denominator
        else "N/A (no step fields to compare)"
    )
    return (
        f"Public sample rows compared: {len(overlap)} of {len(gold)}\n"
        f"Case-level status accuracy: {percentage(status_ok, len(overlap))}\n"
        f"Exact steps_json accuracy: {percentage(exact_steps, len(overlap))}\n"
        f"Sequence-length accuracy: {percentage(sequence_ok, len(overlap))}\n"
        f"Step-field accuracy: {percentage(fields_ok, fields_total)}"
    )

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="dataset", help="Path to challenge dataset directory")
    parser.add_argument(
        "--requests",
        default="deletion_requests.csv",
        help="Request CSV path, absolute or relative to --dataset",
    )
    parser.add_argument("--output", default="output.csv", help="Output CSV path")
    args = parser.parse_args()
    dataset = Path(args.dataset).resolve()
    output_path = Path(args.output).resolve()
    requests_path = Path(args.requests)
    if not requests_path.is_absolute():
        dataset_request_path = dataset / requests_path
        requests_path = dataset_request_path if dataset_request_path.is_file() else requests_path.resolve()

    validate_csv_schema(requests_path, {
        "case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"
    })
    requests = read_csv(requests_path)
    identities = read_csv(dataset / "user_identities.csv")
    audit = read_csv(dataset / "user_audit_log.csv")
    activities = read_csv(dataset / "system_activity.csv")
    rules = read_csv(dataset / "deletion_rules.csv")
    by_user, aliases_by_user = build_identity_index(identities, audit)
    evidence = load_evidence(dataset)

    output_rows = []
    for request in requests:
        status, steps = make_case(request, by_user, aliases_by_user, audit, evidence, activities, rules)
        output_rows.append({
            "case_id": request.get("case_id", ""),
            "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))
        })

    errors = validate_output(requests, output_rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(output_rows)

    report_dir = Path(__file__).resolve().parent / "evaluation"
    report_dir.mkdir(parents=True, exist_ok=True)
    try:
        evaluation = evaluate_sample(dataset, output_rows)
    except (FileNotFoundError, ValueError) as exc:
        evaluation = f"Sample evaluation error: {exc}"
        errors.append(evaluation)
    (report_dir / "evaluation_report.md").write_text(
        "# Evaluation Report\n\n"
        f"- Request input: `{requests_path}`\n\n"
        "## Automated public-sample evaluation\n\n" + evaluation + "\n\n"
        "## Structural validation\n\n"
        f"- Requests: {len(requests)}\n- Output rows: {len(output_rows)}\n"
        f"- Evidence records indexed: {len(evidence)}\n"
        f"- Structural errors: {len(errors)}\n"
        + ("\n".join(f"- ERROR: {e}" for e in errors) if errors else "- No structural errors found.")
        + "\n\n## Limitations and improvements\n\n"
        "- This version uses a deterministic, evidence-grounded rules engine rather than a hosted LLM, so token usage is zero and results are reproducible.\n"
        "- PDF text extraction requires `pypdf`; image OCR requires Pillow, pytesseract, and the Tesseract binary. Missing image OCR is reported as a warning and may reduce evidence coverage.\n"
        "- Public sample comparisons use exact matching case_id values; runs with no overlap are reported as not run rather than as a 0/0 success.\n",
        encoding="utf-8"
    )
    (report_dir / "usage_report.md").write_text(
        "# Token Usage and Cost Report\n\n"
        "- Run type: deterministic local rules engine\n"
        "- Model provider/name: none\n"
        "- Model calls: 0\n"
        "- Input tokens: 0\n"
        "- Output tokens: 0\n"
        "- Total tokens: 0\n"
        f"- Requests processed: {len(requests)}\n"
        "- Average tokens per request: 0\n"
        "- Estimated total model cost: $0.00\n"
        "- Estimated cost per request: $0.00\n\n"
        "No LLM or external API is called by this implementation. If a model is added later, update this report with measured provider usage and pricing for the final run.\n",
        encoding="utf-8"
    )
    print(f"Loaded {len(requests)} requests, {len(evidence)} evidence records.")
    print(f"Wrote {len(output_rows)} rows to {output_path}")
    print(evaluation)
    if errors:
        print("Structural validation errors:")
        for e in errors:
            print(" -", e)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
