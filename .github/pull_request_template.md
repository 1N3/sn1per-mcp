## What this changes

<!-- A short description of the change and why it is needed. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`, Developer Certificate of Origin).
- [ ] Tests are added or updated, and `make test` passes. Tests never run a real Sn1per,
      real `sudo`, or touch the network; they use the stubs and synthetic fixtures.
- [ ] Documentation under `docs/` (and `README.md` if needed) is updated.
- [ ] Documented behaviour affected (the `docs/` page and section, or "none"):
- [ ] No targets, hostnames, loot, credentials or secret-shaped values are included.
      Examples use `.example` or `.test` names and RFC 5737 addresses.
