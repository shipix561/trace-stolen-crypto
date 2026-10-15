# Keeping the labels up to date

`python labels_tool.py sync` downloads every source in `sources.json` that has a `url` (the OFAC sanctions list, and any government page you add) and merges the addresses into `labels.json`. Your own labels and the official exchange labels are never removed.

Windows (once a week): open Task Scheduler > Create Basic Task > Weekly > Start a program > pick `UPDATE-LABELS.bat`.
Linux server (paid site): `0 3 * * 1  cd /opt/tracer && python3 labels_tool.py sync >> sync.log 2>&1`

Add a government page: in `sources.json` copy the "Government notice (example)" block, set `url`, `label`, `category` and `"enabled": true`.
One-off: `python labels_tool.py import-text FILE --source "FBI notice" --url LINK --category scam`
