# Deployment Reference

This reference explains how the components fit together. **Execution is limited to the rights holder or users with separate written authorization.** Reading these instructions does not grant permission to run, deploy, or modify the software. See [LICENSE](LICENSE).

## Start with an isolated environment

The edition consists of a Web client, a Node.js backend, SQLite, and local ciphertext storage. It does not require email, payment, or private storage services.

Use a fresh data directory or volume. Do not import a live database. Retained quota-cleanup logic can delete eligible ciphertext, so production data must not be used for verification.

## Docker Compose

You need Docker Engine or Docker Desktop with Compose. On Windows, use Linux containers.

```sh
docker compose up -d --build
docker compose logs --tail=50 share
```

The default host binding is `127.0.0.1:8191`. The application runs as the non-root `node` user. The `share-data` volume stores SQLite records, ciphertext, avatars, and the registration-code database.

Copy `.env.example` to `.env` before changing configuration:

- PowerShell: `Copy-Item .env.example .env`
- Linux: `cp .env.example .env`

Available settings include:

- `PUBLIC_URL`: the actual browser-facing address; locally, `http://localhost:8191`.
- `ADMIN_PASSWORD`: empty by default, leaving administrator password sign-in disabled. Set an independent strong password if needed.
- `USER_QUOTA_BYTES`: 5 GiB for new accounts by default.

## Registration

An authorized administrator can issue a code:

```sh
docker compose exec share node scripts/enroll.mjs person@example.com
```

The code appears only in the terminal. It is bound to the specified email string, expires after 15 minutes, and allows at most five attempts. Share it privately with the intended user. It does not verify mailbox ownership.

The user sets their own sign-in and encryption passwords in their browser. Administrators should not collect encryption passwords. A verified code is consumed immediately; if registration subsequently fails, issue another code.

## Running without Docker

Use Node.js 22, preferably 22.13 or newer, and npm. If a prebuilt better-sqlite3 binary is unavailable, Python 3, make, and a C++ toolchain are required.

```sh
npm ci
npm test
npm start
```

In a separate terminal, run `node scripts/enroll.mjs person@example.com`.

Run from the repository root: resource paths depend on the working directory. The default data path is `data/`. Direct `npm start` does not automatically load `.env`; supply variables through the calling environment.

## HTTPS and proxies

For public access, use HTTPS and a reverse proxy to the local application port. Set `PUBLIC_URL` to the actual HTTPS origin and recreate the container to apply configuration.

Web Crypto and Passkeys require a secure context. Localhost is a development exception; ordinary HTTP on a LAN address is not an equivalent replacement. This edition trusts its Web origin and does not include Android associations.

Configure the proxy for streamed chunk uploads, appropriate request-size and rate limits, and no API response caching. Do not expose authentication cookies in logs. The server uses `trust proxy = 1`, which assumes one trusted proxy hop; adjust this for the actual network rather than trusting arbitrary forwarded headers.

## Preserving your data

Use `docker compose stop` to stop the service and `docker compose up -d` to restart it. **Do not use `docker compose down -v` when you need to retain data: it removes the volume.**

For backups, stop the application and preserve the full data volume, or coordinate a consistent SQLite backup with ciphertext snapshots. Copying a live database file alone may omit WAL changes and associated files.

Local storage uses `data/files/<user_id>/`. Upload completion can concatenate encrypted chunks into one `.bin` file while retaining chunk boundaries in the database. The number of files on disk is therefore not the chunk count. Preserve both the database and ciphertext; readable recovery also requires appropriate user keys.

## Checks and limitations

`npm test` covers encryption functions, integrity rejection, enrollment behavior, and static resources. `node scripts/smoke.mjs` starts an isolated temporary service on port 18292, checks registration and chunk transfers, and removes its own temporary data.

See [VERIFICATION.md](VERIFICATION.md) for evidence and gaps. Tests do not replace browser, authenticator, security, or long-running transfer assessments.

Email recovery, payments, and private storage adapters are unavailable. Related entry points fail explicitly rather than bypassing verification. Policy placeholders are not ready-to-use legal terms.
