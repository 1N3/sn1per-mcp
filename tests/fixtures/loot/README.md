# Synthetic loot fixtures (contract O.4)

Hand-written, synthetic Sn1per loot laid out like the real trees (J.3):

- `ce-9.2/workspace/` - Community Edition 9.2 layout (bare `ports-<host>.txt`, no `open-ports`, no httpx).
- `se-11.x/workspace/` - 11.x layout (adds `open-ports-<host>.txt`, `httpx-<host>.json`,
  `nuclei-technologies-<host>.txt`, `ai-findings-combined.csv`).

Each has the workspaces `app.example` and `192.0.2.0-24` (hosts `192.0.2.1` and `192.0.2.12`,
to prove exact host matching) and a `credentials/` canary that no reader may return.
Names follow the example-value rule (`.example` names, RFC 5737 addresses). Secret-shaped
values are never committed: tests generate them at run time. Symlinks, hard links, FIFOs
and permission traps are created at test time, never committed.
