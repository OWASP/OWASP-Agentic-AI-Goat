# Database

**Creating / resetting all app databases:** use **[db/initialize-db](initialize-db/README.md)**. From project root run:

```bash
npm run db:initialize-all
```

This creates all SQLite databases under `server/database/` from the schemas and seeds in `db/initialize-db/`.

---

The `db/` folder also contains legacy Postgres/Knex artifacts (`knexfile.js`, `migrations/`, `seeds/`, `schema.sql`). The app runtime uses SQLite and `db/initialize-db`; the Postgres workflow and its scripts have been removed.
