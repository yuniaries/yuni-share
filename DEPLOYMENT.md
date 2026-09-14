# Deployment Reference

This page describes the application's requirements for readers inspecting its architecture. Running or deploying the software requires ownership or separate written authorization under [LICENSE](LICENSE).

## What is included?

The repository includes the Web client, Node.js application server, dependency manifests, and application modules from the dated production snapshot. It does not contain a ready-to-run copy of production infrastructure.

## Runtime requirements

The application uses Node.js, Express, better-sqlite3, and browser Web Crypto. Install dependencies according to `package-lock.json` in an appropriately authorized environment. Native dependency installation may require a compiler and Python when compatible prebuilt binaries are unavailable.

The server resolves public assets relative to its working directory, so its working directory must be the repository root.

## Environment configuration

Configuration is read from environment variables in `server.mjs`. No production values are supplied.

- `PORT`, `PUBLIC_URL`, and `DATA_ROOT` configure the listener, browser-facing origin, and data location.
- `USER_QUOTA_BYTES` and `DISK_RESERVE_BYTES` control storage limits.
- `ADMIN_USERNAME` and `ADMIN_PASSWORD` configure separate administrator access.
- `MAIL_API_URL`, `MAIL_API_TOKEN`, `MAIL_SCOPE`, and `MAIL_TRANSACTIONAL_API_URL` configure external verification and notification services.
- `PAYMENT_API_ROOT`, `PAYMENT_MERCHANT_NUM`, `PAYMENT_SECRET`, and `PAYMENT_PAY_TYPE` configure payment integration.
- `STORAGE_API_URL`, `STORAGE_API_TOKEN`, and `STORAGE_POOL_ID` configure external storage.
- `WEBAUTHN_RP_ID` configures the relying-party identifier.

Consult the source for defaults and validation. Keeping the call paths does not provide the external services themselves. Without the necessary integrations, some workflows will be unavailable.

## Browser and authentication requirements

Web Crypto and Passkey operations require a supported secure context. Public deployments need HTTPS. Production Android associations and public origin-related constants are retained for source fidelity; they do not authorize another deployment to act as the original service.

## Data safety

Use a new isolated data directory for any separately authorized assessment. Do not point a test instance at production data: migrations, retention rules, and cleanup tasks can modify or remove records and files.

Back up databases consistently together with their ciphertext. Copying only a live SQLite database can omit WAL changes. Local storage may combine multiple encrypted chunks into one file, with chunk boundaries recorded in the database. External storage uses a separate service.

This repository deliberately excludes environment files, service credentials, databases, and user uploads. Do not add them to a public fork or report.
