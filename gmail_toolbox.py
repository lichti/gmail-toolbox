#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gmail Toolbox - One-file CLI utility

Options (flags & arguments)
===========================
Search & Time Bounds
- --search <string> or @<criteria.json>       : Gmail raw query or JSON with {"criteria": {...}} (Gmail filter syntax).
- --since <YYYY-MM-DD>                         : Adds after:YYYY/MM/DD (inclusive) to the query.
- --until <YYYY-MM-DD>                         : Adds before:YYYY/MM/DD (exclusive) to the query.
- --unread-only                                : Adds is:unread to the query.
- --limit <N>                                  : Maximum number of messages to fetch/process.

Output & Logging
- --timezone <TZ>                              : Timezone for date display (default: America/Sao_Paulo).
- --save-log                                   : Save console output to ./output/search_<date>_<time>.log (live).
- --skip-live-print                            : Do NOT print per-message "Counter | email | date | subject"; keep totals and summaries.
- --export-json <file.json>                    : Export matched messages [{email, date_iso, subject, id}].
- --export-csv <file.csv>                      : Export matched messages as CSV (email,date_iso,subject,id).

Grouping & Listings
- --group-by-email                             : After live results, print a grouped summary "Qty | E-mail" (desc).
                                                 With --export-json/--export-csv also writes grouped_ files.
- --list-labels                                : List all labels (id, name).
- --list-filters                               : List all Gmail settings filters (id + main criteria).

Message Mutations (require --search)
- --archive                                    : Remove INBOX (archive).
- --unarchive                                  : Add INBOX (move back to inbox).
- --apply-label <name>                         : Create if missing and apply to matched messages.
- --remove-label <name>                        : Remove an existing custom label from matched messages.
- --mark-read                                  : Remove UNREAD.
- --mark-unread                                : Add UNREAD.
- --delete                                     : Delete matched messages (destructive; requires --yes-i-know).
- --batch-size <N>                             : Batch size for batchModify/batchDelete (default 1000).
- --dry-run                                    : Print planned actions without modifying.

Gmail Settings Filters
- --create-filter <action string> or @<action.json>
                                               : Creates a Gmail settings filter using criteria from --search @criteria.json.
                                                 Action string example: "addLabel=automated_hide,removeLabel=INBOX,markRead=true".
- --retroactive-filter-action                   : After creating the filter, apply its action to current matches (requires --yes-i-know).
- --delete-filter <id>                          : Delete an existing filter by id (destructive; requires --yes-i-know).

Safety
- --yes-i-know                                 : Required for destructive actions (--delete, --delete-filter, --retroactive-filter-action).

Show / Inspect
- --show-message <id>                           : Show message in 'full' format (selected headers + snippet).
- --show-message-metadata <id>                  : Show message in 'metadata' format (selected headers).
- --show-raw <id>                               : Show base64url RFC822 ('raw') of a message.

Download Attachments
- --download-attachments <id> --dir <path>      : Download all attachments to directory (created if missing).
- --download-inline                             : Also save inline parts that have body.data.
- --download-prefix <str>                       : Prefix filenames on save (e.g., "export_").
- --download-mime-contains <text>               : Only download parts whose MIME contains text (case-insensitive), e.g., "image/" or "pdf".
- --download-filename-contains <text>           : Only download parts whose filename contains text (case-insensitive).

All console/log messages are in English.
"""

import os
import sys
import csv
import json
import time
import base64
import argparse
import pathlib
from typing import List, Dict, Any, Optional, Tuple
from email.utils import parseaddr
from datetime import datetime, timezone
from collections import defaultdict

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:
    ZoneInfo = None

from google.oauth2.credentials import Credentials
# pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

# -----------------------------
# Config
# -----------------------------
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.settings.basic",
]
TOKEN_FILE = "token_toolbox.json"
DEFAULT_TZ = "America/Sao_Paulo"
OUTPUT_DIR = pathlib.Path("output")


# -----------------------------
# Logging helpers
# -----------------------------
class LiveLogger:
    def __init__(self, save_log: bool):
        self.save_log = save_log
        self.file = None
        if save_log:
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.path = OUTPUT_DIR / f"search_{ts}.log"
            self.file = open(self.path, "w", encoding="utf-8")
            self.log(f"# Log started at {ts}")
        else:
            self.path = None

    def log(self, msg: str):
        print(msg, flush=True)
        if self.file:
            self.file.write(msg + "\n")
            self.file.flush()

    def close(self):
        if self.file:
            self.log("# Log closed")
            self.file.close()


# -----------------------------
# Gmail service
# -----------------------------
def gmail_service(logger: LiveLogger):
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logger.log("[auth] Refreshing token...")
            creds.refresh(Request())
        else:
            if not os.path.exists("credentials.json"):
                logger.log("[error] Missing 'credentials.json' in current folder.")
                sys.exit(1)
            logger.log("[auth] Launching OAuth flow (Desktop)...")
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())
            logger.log(f"[auth] Token saved to {TOKEN_FILE}")
    svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
    logger.log("[auth] Gmail service ready")
    return svc


# -----------------------------
# Parsing helpers
# -----------------------------
def load_json_from_at_arg(arg: str) -> Dict[str, Any]:
    if not arg.startswith("@"):
        raise ValueError("Expected an @<file.json> argument.")
    path = arg[1:]
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_action_string(s: str) -> Dict[str, Any]:
    """
    Parses a concise action string into a Gmail API action object.
    Example: addLabel=automated_hide,removeLabel=INBOX,markRead=true
    """
    action = {"addLabelIds": [], "removeLabelIds": []}
    for part in s.split(","):
        k, _, v = part.strip().partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "addlabel":
            action.setdefault("_addLabelNames", []).append(v)
        elif k == "removelabel":
            action.setdefault("_removeLabelNames", []).append(v)
        elif k == "markread":
            if v.lower() in ("true", "1", "yes"):
                action["removeLabelIds"].append("UNREAD")
        elif k == "markimportant":
            if v.lower() in ("true", "1", "yes"):
                action["addLabelIds"].append("IMPORTANT")
            else:
                action["removeLabelIds"].append("IMPORTANT")
    return action


def build_query_from_criteria(criteria: Dict[str, Any]) -> str:
    parts = []
    if not criteria:
        return ""
    if criteria.get("query"):
        parts.append(criteria["query"].strip())
    if criteria.get("from"):
        parts.append(f'from:{criteria["from"].strip()}')
    if criteria.get("to"):
        parts.append(f'to:{criteria["to"].strip()}')
    if criteria.get("subject"):
        subj = criteria["subject"].replace('"', r'\"').strip()
        parts.append(f'subject:\"{subj}\"')
    if criteria.get("hasAttachment"):
        parts.append("has:attachment")
    size = criteria.get("size")
    size_cmp = (criteria.get("sizeComparison") or "").lower()
    if isinstance(size, int) and size > 0:
        if size_cmp in ("larger", "greater_than", "gt", "greater-than"):
            parts.append(f"larger:{size}")
        elif size_cmp in ("smaller", "less_than", "lt", "less-than"):
            parts.append(f"smaller:{size}")
    if criteria.get("negatedQuery"):
        nq = criteria["negatedQuery"].strip()
        parts.append(f'-({nq})' if (" " in nq or ":" in nq) else f'-{nq}')
    return " ".join(p for p in parts if p).strip()


def add_date_bounds_to_query(query: str, since: Optional[str], until: Optional[str]) -> str:
    """Append after:/before: to Gmail query using YYYY/MM/DD; returns new query string."""
    extra = []
    def ymd_to_slash(s: str) -> str:
        return s.replace("-", "/").strip()
    if since:
        extra.append(f"after:{ymd_to_slash(since)}")
    if until:
        extra.append(f"before:{ymd_to_slash(until)}")
    return " ".join(p for p in [query] + extra if p).strip()


# -----------------------------
# Gmail primitives
# -----------------------------
def list_labels(svc) -> List[Dict[str, Any]]:
    resp = svc.users().labels().list(userId="me").execute()
    return resp.get("labels", [])


def get_label_id_by_name(svc, name: str) -> Optional[str]:
    for lb in list_labels(svc):
        if lb["name"].lower() == name.lower():
            return lb["id"]
    return None


def get_or_create_label_id(svc, name: str, logger: LiveLogger) -> str:
    lbid = get_label_id_by_name(svc, name)
    if lbid:
        return lbid
    body = {
        "name": name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    }
    created = svc.users().labels().create(userId="me", body=body).execute()
    logger.log(f"[labels] Created label '{name}' (id={created['id']})")
    return created["id"]


def list_filters(svc) -> List[Dict[str, Any]]:
    try:
        resp = svc.users().settings().filters().list(userId="me").execute()
        return resp.get("filter", [])
    except HttpError as e:
        if e.resp.status == 404:
            return []
        raise


def delete_filter(svc, fid: str, logger: LiveLogger, dry_run: bool):
    logger.log(f"[filters] Deleting filter id={fid}, dry_run={dry_run}")
    if dry_run:
        return
    svc.users().settings().filters().delete(userId="me", id=fid).execute()
    logger.log(f"[filters] Filter deleted id={fid}")


def list_message_ids(svc, query: str, limit: Optional[int], logger: LiveLogger) -> List[str]:
    ids = []
    page = None
    logger.log(f"[search] Query: {query}")
    while True:
        resp = svc.users().messages().list(
            userId="me", q=query, maxResults=500, pageToken=page
        ).execute()
        chunk = [m["id"] for m in resp.get("messages", [])]
        ids.extend(chunk)
        logger.log(f"[search] Retrieved {len(chunk)} ids (total={len(ids)})")
        page = resp.get("nextPageToken")
        if limit and len(ids) >= limit:
            ids = ids[:limit]
            break
        if not page:
            break
    logger.log(f"[search] Done. Matched={len(ids)}")
    return ids


def fetch_msg_triplet(svc, msg_id: str) -> Tuple[str, int, str]:
    msg = svc.users().messages().get(
        userId="me", id=msg_id, format="metadata", metadataHeaders=["From", "Subject", "Date"]
    ).execute()
    headers = {h["name"].lower(): h["value"] for h in msg["payload"].get("headers", [])}
    sender_email = parseaddr(headers.get("from", ""))[1] or "(unknown)"
    subject = headers.get("subject", "(no subject)")
    ts = int(msg.get("internalDate", "0"))
    return sender_email, ts, subject


def datetime_from_ms(ts_ms: int, tz_name: str) -> str:
    dt_utc = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    if ZoneInfo:
        dt_local = dt_utc.astimezone(ZoneInfo(tz_name))
    else:
        dt_local = dt_utc.astimezone()
    return dt_local.strftime("%Y-%m-%d %H:%M:%S")


def batch_modify(svc, ids: List[str], add: List[str], remove: List[str], batch_size: int, logger: LiveLogger, dry_run: bool):
    if not ids:
        logger.log("[modify] Nothing to modify.")
        return
    logger.log(f"[modify] addLabelIds={add or []}, removeLabelIds={remove or []}, ids={len(ids)}, batch_size={batch_size}, dry_run={dry_run}")
    if dry_run:
        return
    for i in range(0, len(ids), batch_size):
        chunk = ids[i:i + batch_size]
        body = {"ids": chunk}
        if add:
            body["addLabelIds"] = add
        if remove:
            body["removeLabelIds"] = remove
        svc.users().messages().batchModify(userId="me", body=body).execute()
        logger.log(f"[modify] Modified {len(chunk)} messages ({i+len(chunk)}/{len(ids)})")
        time.sleep(0.1)


def batch_delete(svc, ids: List[str], batch_size: int, logger: LiveLogger, dry_run: bool):
    if not ids:
        logger.log("[delete] Nothing to delete.")
        return
    logger.log(f"[delete] Deleting {len(ids)} messages, batch_size={batch_size}, dry_run={dry_run}")
    if dry_run:
        return
    for i in range(0, len(ids), batch_size):
        chunk = ids[i:i + batch_size]
        svc.users().messages().batchDelete(userId="me", body={"ids": chunk}).execute()
        logger.log(f"[delete] Deleted {len(chunk)} messages ({i+len(chunk)}/{len(ids)})")
        time.sleep(0.1)


def resolve_action_labels(svc, action_obj: Dict[str, Any], logger: LiveLogger) -> Dict[str, Any]:
    action = json.loads(json.dumps(action_obj))  # deep copy
    add_names = action.pop("_addLabelNames", [])
    remove_names = action.pop("_removeLabelNames", [])
    for name in add_names:
        lbid = get_or_create_label_id(svc, name, logger)
        action.setdefault("addLabelIds", []).append(lbid)
    for name in remove_names:
        lbid = get_label_id_by_name(svc, name)
        if lbid:
            action.setdefault("removeLabelIds", []).append(lbid)
        else:
            action.setdefault("removeLabelIds", []).append(name.upper())
    return action


def print_message_full(svc, msg_id: str, logger: LiveLogger):
    msg = svc.users().messages().get(userId="me", id=msg_id, format="full").execute()
    headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
    snippet = msg.get("snippet", "")
    logger.log(f"[message full] id={msg_id}")
    for k in ("From", "To", "Date", "Subject", "Message-ID"):
        if k in headers:
            logger.log(f"  {k}: {headers[k]}")
    logger.log(f"  Snippet: {snippet}")
    logger.log("  (payload parts omitted)")


def print_message_metadata(svc, msg_id: str, logger: LiveLogger):
    msg = svc.users().messages().get(
        userId="me", id=msg_id, format="metadata", metadataHeaders=["From", "To", "Date", "Subject", "Message-ID"]
    ).execute()
    headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
    logger.log(f"[message metadata] id={msg_id}")
    for k in ("From", "To", "Date", "Subject", "Message-ID"):
        if k in headers:
            logger.log(f"  {k}: {headers[k]}")


def print_message_raw(svc, msg_id: str, logger: LiveLogger):
    msg = svc.users().messages().get(userId="me", id=msg_id, format="raw").execute()
    raw_b64url = msg.get("raw", "")
    logger.log(f"[message raw] id={msg_id}")
    logger.log(raw_b64url if raw_b64url else "(no raw content)")


def _iter_parts(payload: Dict[str, Any]):
    """Yield all parts recursively (including nested .parts)."""
    if not payload:
        return
    stack = [payload]
    while stack:
        p = stack.pop()
        yield p
        for child in (p.get("parts") or []):
            stack.append(child)


def _safe_filename(name: str, fallback: str) -> str:
    name = (name or "").strip() or fallback
    return "".join(ch for ch in name if ch not in '\\/:*?"<>|').strip() or fallback


def download_attachments(
    svc,
    msg_id: str,
    outdir: pathlib.Path,
    logger: LiveLogger,
    include_inline: bool = False,
    prefix: str = "",
    mime_contains: Optional[str] = None,
    filename_contains: Optional[str] = None,
):
    outdir.mkdir(parents=True, exist_ok=True)
    msg = svc.users().messages().get(userId="me", id=msg_id, format="full").execute()
    payload = msg.get("payload", {})
    found = 0

    mime_filter = (mime_contains or "").lower().strip()
    fname_filter = (filename_contains or "").lower().strip()

    for part in _iter_parts(payload):
        filename = part.get("filename") or ""
        body = part.get("body") or {}
        att_id = body.get("attachmentId")
        mime_type = (part.get("mimeType") or "").lower()

        # Skip container parts
        if mime_type.startswith("multipart/"):
            continue

        # MIME filter
        if mime_filter and mime_filter not in mime_type:
            continue

        data_bytes = None
        target_name = None

        if att_id:
            # Attachment by id
            att = svc.users().messages().attachments().get(
                userId="me", messageId=msg_id, id=att_id
            ).execute()
            data_b64 = att.get("data", "")
            if data_b64:
                data_bytes = base64.urlsafe_b64decode(data_b64.encode("utf-8"))
            target_name = filename or "attachment"

        elif include_inline and body.get("data"):
            # Inline content in body.data
            data_b64 = body.get("data", "")
            data_bytes = base64.urlsafe_b64decode(data_b64.encode("utf-8"))
            ext = ""
            if "/" in mime_type and not filename:
                ext = "." + mime_type.split("/", 1)[1].lower().split(";")[0].strip()
            target_name = filename or ("inline_part" + ext)

        if data_bytes is None:
            continue

        # Filename filter
        base_name = _safe_filename(str(target_name), f"attachment_{found+1}")

        if fname_filter and fname_filter not in base_name.lower():
            continue

        if prefix:
            base_name = f"{prefix}{base_name}"
        target = outdir / base_name

        # Avoid overwrite
        if target.exists():
            stem = target.stem
            suf = target.suffix
            idx = 2
            while True:
                alt = outdir / f"{stem}({idx}){suf}"
                if not alt.exists():
                    target = alt
                    break
                idx += 1

        with open(target, "wb") as f:
            f.write(data_bytes)

        found += 1
        logger.log(f"[attachments] Saved: {target}")

    if found == 0:
        logger.log("[attachments] No attachments found after filters.")
    else:
        logger.log(f"[attachments] Done. Saved {found} file(s).")


# -----------------------------
# Main CLI
# -----------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Gmail Toolbox - search, label, archive, delete, show, download, and manage filters from one CLI.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Search inputs
    ap.add_argument("--search", help="Raw Gmail query string or @<criteria.json> (Gmail filter body with 'criteria').")
    ap.add_argument("--since", help="Restrict search to messages after YYYY-MM-DD (inclusive).")
    ap.add_argument("--until", help="Restrict search to messages before YYYY-MM-DD (exclusive).")

    # Actions on messages
    ap.add_argument("--archive", action="store_true", help="Archive matched messages (remove INBOX). Requires --search.")
    ap.add_argument("--unarchive", action="store_true", help="Unarchive matched messages (add INBOX). Requires --search.")
    ap.add_argument("--apply-label", help="Apply a label to matched messages (creates if missing). Requires --search.")
    ap.add_argument("--remove-label", help="Remove a label from matched messages. Requires --search.")
    ap.add_argument("--mark-read", action="store_true", help="Mark matched messages as read. Requires --search.")
    ap.add_argument("--mark-unread", action="store_true", help="Mark matched messages as unread. Requires --search.")
    ap.add_argument("--delete", action="store_true", help="Delete matched messages. Requires --search and --yes-i-know.")

    # Filters
    ap.add_argument("--create-filter", help="Action string (e.g. addLabel=foo,removeLabel=INBOX,markRead=true) or @<action.json>. Requires --search.")
    ap.add_argument("--retroactive-filter-action", action="store_true", help="After creating the filter, apply its action to the currently matched messages (requires --yes-i-know).")
    ap.add_argument("--delete-filter", help="Delete a Gmail settings filter by id (requires --yes-i-know).")

    # Safety
    ap.add_argument("--yes-i-know", action="store_true", help="Safety confirmation: allows destructive/retroactive modifications.")
    ap.add_argument("--dry-run", action="store_true", help="Do not modify anything; just print planned actions.")

    # Grouping / Listing
    ap.add_argument("--group-by-email", action="store_true", help="Also print a grouped summary (Qty | E-mail) sorted by Qty desc; when exporting, writes grouped_ files.")
    ap.add_argument("--list-labels", action="store_true", help="List all labels (id, name).")
    ap.add_argument("--list-filters", action="store_true", help="List all Gmail settings filters.")

    # Output & control
    ap.add_argument("--save-log", action="store_true", help="Save console output into ./output/search_<date>_<time>.log.")
    ap.add_argument("--timezone", default=DEFAULT_TZ, help="Timezone for displaying dates.")
    ap.add_argument("--limit", type=int, help="Limit number of messages processed in search.")
    ap.add_argument("--unread-only", action="store_true", help="Restrict search results to unread (adds 'is:unread').")
    ap.add_argument("--export-json", help="Export matched messages to a JSON file (email, date_iso, subject, id).")
    ap.add_argument("--export-csv", help="Export matched messages to a CSV file (email,date_iso,subject,id).")
    ap.add_argument("--batch-size", type=int, default=1000, help="Batch size for batchModify/batchDelete (Gmail max=1000).")
    ap.add_argument("--skip-live-print", action="store_true", help="Do not print per-message lines; only final totals/summaries.")

    # Show / Inspect / Download
    ap.add_argument("--show-message", help="Show one message in 'full' format by id.")
    ap.add_argument("--show-message-metadata", help="Show one message in 'metadata' format by id.")
    ap.add_argument("--show-raw", help="Show one message in 'raw' format (base64url) by id.")
    ap.add_argument("--download-attachments", help="Download all attachments from a message by id.")
    ap.add_argument("--dir", help="Directory for --download-attachments (will be created).")
    ap.add_argument("--download-inline", action="store_true", help="Also download inline parts that have body.data (base64).")
    ap.add_argument("--download-prefix", help="Prefix filenames when saving attachments/inline parts (e.g., 'export_').")
    ap.add_argument("--download-mime-contains", help="Filter downloads by MIME substring (case-insensitive), e.g. 'image/' or 'pdf'.")
    ap.add_argument("--download-filename-contains", help="Filter downloads by filename substring (case-insensitive).")

    args = ap.parse_args()
    logger = LiveLogger(save_log=args.save_log)
    try:
        svc = gmail_service(logger)

        # Show/inspect/download (independent)
        if args.show_message:
            print_message_full(svc, args.show_message, logger)
        if args.show_message_metadata:
            print_message_metadata(svc, args.show_message_metadata, logger)
        if args.show_raw:
            print_message_raw(svc, args.show_raw, logger)
        if args.download_attachments:
            if not args.dir:
                logger.log("[attachments] --dir <path> is required with --download-attachments.")
                sys.exit(1)
            download_attachments(
                svc,
                args.download_attachments,
                pathlib.Path(args.dir),
                logger,
                include_inline=args.download_inline,
                prefix=(args.download_prefix or ""),
                mime_contains=(args.download_mime_contains or None),
                filename_contains=(args.download_filename_contains or None),
            )

        # Optional lists (independent)
        if args.list_labels:
            labels = list_labels(svc)
            logger.log("[labels] Listing labels:")
            for lb in labels:
                logger.log(f"  - id={lb['id']} | name={lb['name']}")
        if args.list_filters:
            flts = list_filters(svc)
            logger.log("[filters] Listing filters:")
            if not flts:
                logger.log("  (none)")
            for f in flts:
                fid = f.get("id")
                crit = f.get("criteria", {})
                parts = []
                if crit.get("query"): parts.append(f"query={crit.get('query')}")
                if crit.get("from"): parts.append(f"from={crit.get('from')}")
                if crit.get("to"): parts.append(f"to={crit.get('to')}")
                if crit.get("subject"): parts.append(f"subject={crit.get('subject')}")
                logger.log(f"  - id={fid} | " + (", ".join(parts) if parts else "(no criteria)"))

        # Build query from --search (+ since/until)
        query = None
        criteria_body = None
        if args.search:
            if args.search.startswith("@"):
                body = load_json_from_at_arg(args.search)
                if not isinstance(body, dict) or "criteria" not in body:
                    logger.log("[error] Criteria JSON must contain a 'criteria' object.")
                    sys.exit(1)
                criteria_body = body["criteria"]
                query = build_query_from_criteria(criteria_body)
                if not query:
                    logger.log("[error] Empty criteria produced no query.")
                    sys.exit(1)
            else:
                query = args.search.strip()

            if args.unread_only:
                query = (query + " is:unread").strip()
            if args.since or args.until:
                query = add_date_bounds_to_query(query, args.since, args.until)

        # Actions that require search
        action_requires_search = any([
            args.archive, args.unarchive, args.apply_label, args.remove_label,
            args.mark_read, args.mark_unread, args.create_filter,
            args.export_json, args.export_csv, args.group_by_email,
            args.retroactive_filter_action, args.delete
        ])
        if action_requires_search and not query:
            logger.log("[error] This action requires --search.")
            sys.exit(1)

        # Search path
        matched_ids: List[str] = []
        triplets: List[Tuple[str, str, str, str]] = []  # (email, date_str, subject, id)
        group_counts: Dict[str, int] = defaultdict(int)

        if query:
            matched_ids = list_message_ids(svc, query, args.limit, logger)
            counter = 0
            for mid in matched_ids:
                try:
                    em, ts_ms, subj = fetch_msg_triplet(svc, mid)
                    date_str = datetime_from_ms(ts_ms, args.timezone)
                    triplets.append((em, date_str, subj, mid))
                    group_counts[em] += 1
                    counter += 1
                    if not args.skip_live_print:
                        logger.log(f"{counter} | {em} | {date_str} | {subj}")
                    if counter % 200 == 0:
                        time.sleep(0.05)
                except HttpError as e:
                    logger.log(f"# WARN: failed to read message {mid}: {e}")
                    continue

            logger.log(f"\nTotal messages matched: {len(matched_ids)}")

            if args.group_by_email:
                logger.log("\nGrouped summary (Qty | E-mail):")
                ordered = sorted(group_counts.items(), key=lambda kv: (-kv[1], kv[0]))
                for em, qty in ordered:
                    logger.log(f"{qty} | {em}")

                # grouped exports
                if args.export_json:
                    with open(args.export_json, "w", encoding="utf-8") as jf:
                        json.dump(
                            [{"email": a, "date_iso": b, "subject": c, "id": d} for (a,b,c,d) in triplets],
                            jf, ensure_ascii=False, indent=2
                        )
                    logger.log(f"[export] JSON saved: {args.export_json}")
                    gjson = pathlib.Path(args.export_json)
                    gjson_path = gjson.with_name("grouped_" + gjson.name)
                    with open(gjson_path, "w", encoding="utf-8") as gj:
                        json.dump(
                            [{"email": em, "qty": qty} for em, qty in ordered],
                            gj, ensure_ascii=False, indent=2
                        )
                    logger.log(f"[export] Grouped JSON saved: {gjson_path}")

                if args.export_csv:
                    with open(args.export_csv, "w", encoding="utf-8", newline="") as cf:
                        w = csv.writer(cf)
                        w.writerow(["email", "date_iso", "subject", "id"])
                        for (a,b,c,d) in triplets:
                            w.writerow([a,b,c,d])
                    logger.log(f"[export] CSV saved: {args.export_csv}")
                    gcsv = pathlib.Path(args.export_csv)
                    gcsv_path = gcsv.with_name("grouped_" + gcsv.name)
                    with open(gcsv_path, "w", encoding="utf-8", newline="") as gcf:
                        w = csv.writer(gcf)
                        w.writerow(["qty", "email"])
                        for em, qty in ordered:
                            w.writerow([qty, em])
                    logger.log(f"[export] Grouped CSV saved: {gcsv_path}")

        # Non-grouped export
        if query and not args.group_by_email:
            if args.export_json and triplets:
                with open(args.export_json, "w", encoding="utf-8") as jf:
                    json.dump(
                        [{"email": a, "date_iso": b, "subject": c, "id": d} for (a,b,c,d) in triplets],
                        jf, ensure_ascii=False, indent=2
                    )
                logger.log(f"[export] JSON saved: {args.export_json}")

            if args.export_csv and triplets:
                with open(args.export_csv, "w", encoding="utf-8", newline="") as cf:
                    w = csv.writer(cf)
                    w.writerow(["email", "date_iso", "subject", "id"])
                    for (a,b,c,d) in triplets:
                        w.writerow([a,b,c,d])
                logger.log(f"[export] CSV saved: {args.export_csv}")

        # Mutations on matched messages
        if matched_ids:
            add_label_ids: List[str] = []
            remove_label_ids: List[str] = []

            if args.archive:
                remove_label_ids.append("INBOX")
            if args.unarchive:
                add_label_ids.append("INBOX")
            if args.mark_read:
                remove_label_ids.append("UNREAD")
            if args.mark_unread:
                add_label_ids.append("UNREAD")
            if args.apply_label:
                lbid = get_or_create_label_id(svc, args.apply_label, logger)
                add_label_ids.append(lbid)
            if args.remove_label:
                lbid = get_label_id_by_name(svc, args.remove_label)
                if lbid:
                    remove_label_ids.append(lbid)
                else:
                    logger.log(f"[labels] Label '{args.remove_label}' not found; skipping removal.")

            if add_label_ids or remove_label_ids:
                batch_modify(svc, matched_ids, add_label_ids, remove_label_ids, args.batch_size, logger, args.dry_run)

            # Delete messages
            if args.delete:
                if not args.yes_i_know:
                    logger.log("[delete] Refused. Add --yes-i-know to confirm deletions.")
                else:
                    batch_delete(svc, matched_ids, args.batch_size, logger, args.dry_run)

        # Create filter (+ optional retroactive)
        if args.create_filter:
            if not criteria_body:
                logger.log("[error] --create-filter requires --search using @criteria.json or a query convertible from criteria.")
                logger.log("        Tip: To create a filter from a raw query, build a minimal criteria JSON with the 'query' field.")
                sys.exit(1)
            # Build action
            if args.create_filter.startswith("@"):
                action_body = load_json_from_at_arg(args.create_filter)
                if not isinstance(action_body, dict):
                    logger.log("[error] Action JSON must be an object.")
                    sys.exit(1)
                action_obj = action_body
            else:
                action_obj = parse_action_string(args.create_filter)

            action_resolved_for_filter = resolve_action_labels(svc, action_obj, logger)
            filter_body = {"criteria": criteria_body, "action": action_resolved_for_filter}
            logger.log(f"[filters] Creating filter with criteria/action...")
            if args.dry_run:
                logger.log("[filters] DRY-RUN -> not creating filter. Body preview:")
                logger.log(json.dumps(filter_body, ensure_ascii=False, indent=2))
            else:
                created = svc.users().settings().filters().create(userId="me", body=filter_body).execute()
                logger.log(f"[filters] Filter created. id={created.get('id')}")

            # Retroactive: apply the same action to matched messages
            if args.retroactive_filter_action:
                if not args.yes_i_know:
                    logger.log("[retroactive] Refused. Add --yes-i-know to confirm retroactive modifications.")
                else:
                    add_ids = action_resolved_for_filter.get("addLabelIds", []) or []
                    remove_ids = action_resolved_for_filter.get("removeLabelIds", []) or []
                    logger.log("[retroactive] Applying filter action to already-matched messages...")
                    batch_modify(svc, matched_ids, add_ids, remove_ids, args.batch_size, logger, args.dry_run)

        # Delete filter by id
        if args.delete_filter:
            if not args.yes_i_know:
                logger.log("[filters] Refused to delete filter. Add --yes-i-know.")
            else:
                delete_filter(svc, args.delete_filter, logger, args.dry_run)

    except HttpError as e:
        if e.resp.status == 403 and b"accessNotConfigured" in (e.content or b""):
            logger.log("ERROR 403: Gmail API not enabled for your credentials project. Enable it and delete token_toolbox.json.")
            sys.exit(1)
        logger.log(f"[fatal] HttpError: {e}")
        sys.exit(2)
    except KeyboardInterrupt:
        logger.log("[abort] Interrupted by user.")
        sys.exit(130)
    finally:
        logger.close()


if __name__ == "__main__":
    main()
