
# Gmail Toolbox (one-file CLI)

A single Python CLI to **search**, **label**, **archive**, **delete**, **show**, **download**, and **manage filters** in Gmail, with **live console logs** and optional log saving.

## Requirements
- `credentials.json` (OAuth Desktop) in the same folder.
- Python 3.9+ recommended.
- Install:
  ```bash
  pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
  ```

## Defaults
- **Timezone:** `America/Sao_Paulo` (override with `--timezone`).
- **Live print:** `Counter | email | date | subject`.

## Quick Start
```bash
python gmail_toolbox.py --list-labels
python gmail_toolbox.py --search 'from:boss@example.com newer_than:1y' --save-log
```

## Search
```bash
python gmail_toolbox.py --search 'in:inbox has:attachment' --limit 200
python gmail_toolbox.py --search @criteria.json
```
`criteria.json`:
```json
{"criteria": {"from": "alerts@example.com", "query": "in:anywhere", "hasAttachment": false}}
```

### Date bounds
```bash
python gmail_toolbox.py --search 'in:inbox' --since 2025-01-01 --until 2025-03-01
```
Notes:
- `--since` → `after:YYYY/MM/DD` (inclusive).
- `--until` → `before:YYYY/MM/DD` (exclusive).

### Output & exports
- `--save-log` writes `./output/search_<date>_<time>.log` live.
- `--export-json results.json` / `--export-csv results.csv`
- `--skip-live-print` hides per-message lines, keeps totals and summaries.

## Group by sender
```bash
python gmail_toolbox.py --search 'in:anywhere' --group-by-email
```
- Prints each match live (unless `--skip-live-print`), then a grouped summary `Qty | E-mail` (desc).
- With export flags, writes extra `grouped_` files.

## Mutations (require `--search`)
```bash
python gmail_toolbox.py --search 'from:news@list.com' --archive
python gmail_toolbox.py --search 'subject:"Invoice"' --apply-label automated_hide
python gmail_toolbox.py --search 'label:automated_hide' --unarchive
python gmail_toolbox.py --search 'older_than:3y' --delete --yes-i-know     # destructive
```
Extras: `--batch-size`, `--dry-run`.

## Create/Delete Gmail Settings Filters
Create (needs `--search` via `@criteria.json`):
```bash
python gmail_toolbox.py --search @criteria.json \
  --create-filter 'addLabel=automated_hide,removeLabel=INBOX,markRead=true'
```
Apply the same action retroactively:
```bash
python gmail_toolbox.py --search @criteria.json \
  --create-filter @action.json \
  --retroactive-filter-action --yes-i-know
```
Delete filter (destructive):
```bash
python gmail_toolbox.py --delete-filter 1234567890 --yes-i-know
```

## Show / Download
```bash
# Show message
python gmail_toolbox.py --show-message <id>            # full
python gmail_toolbox.py --show-message-metadata <id>   # metadata
python gmail_toolbox.py --show-raw <id>                # base64url RFC822

# Download attachments
python gmail_toolbox.py --download-attachments <id> --dir ./attachments

# Options for downloads
--download-inline                    # also save inline (body.data)
--download-prefix exported_          # prefix file names
--download-mime-contains image/      # filter by MIME substring (e.g., image/, pdf)
--download-filename-contains invoice # filter by filename substring
```

Notes:
- Inline parts without filename become `inline_part.<ext>` (if MIME suggests one).
- Existing files get numeric suffixes.
