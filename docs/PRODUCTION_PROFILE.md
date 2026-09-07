# Production profile

Fail closed.

| Gate | Lab | Production |
|------|-----|------------|
| SPIRE | fallback ok | required |
| Measurement | dev:unattested ok | refuse dev:* |
| Outbox | SQLite | Postgres DATABASE_URL |
| Caller override | lab | forbidden |
| Broker start | warns | exits if preflight fails |
