# Yuni Share

Your files, protected before they leave your browser.

Yuni Share is a personal file-storage application with client-side encryption. Your browser encrypts file contents before uploading them and decrypts them when you download. File names, paths, and per-file keys are also stored in encrypted metadata.

This repository lets you examine how that protection works: how keys are created, how files are encrypted in chunks, and how the server controls access to stored ciphertext.

## What you can explore

- **File protection:** independent random file keys and AES-GCM encryption with integrity checks.
- **Private metadata:** encrypted file names, paths, and per-file keys.
- **File management:** uploads, downloads, previews, search, and folders.
- **Account access:** email-based sign-in, password hashing, sessions, username changes, and Web Passkey flows.
- **Chunked transfers:** upload, resumption-related handling, completion checks, and download reconstruction.
- **Storage management:** local ciphertext storage, SQLite records, quotas, and administrative interfaces.

## How your files are protected

### Your encrypted space

Your browser generates a vault key. A separate encryption password is processed with PBKDF2-SHA256 to derive a key that encrypts the vault key. Your sign-in password and encryption password serve different purposes.

### Your files

Each upload receives a random 256-bit file key and a file nonce. Each chunk uses an initialization vector derived from that nonce and its index. Additional authenticated data binds the ciphertext to the upload identifier and chunk index.

When you download a file, the client verifies and decrypts its chunks before reconstructing the content. Format version 2 can apply lossless gzip compression before encryption when supported and beneficial; it does not perform lossy image or video transcoding.

### Your privacy

File content and sensitive file metadata are encrypted, but not every account or storage detail is hidden. The server still handles information such as your email address, timestamps, ciphertext size, some logical sizes, and category hints. Account avatars are outside the file-encryption boundary.

Read [Your Files and Privacy](SECURITY.md) for practical explanations and limitations. Source visibility supports inspection; it is not a security certification or proof that a live website serves identical code.

## Find your way around the code

| Location | What it explains |
| --- | --- |
| [public/app.js](public/app.js) | Client-side key handling, encryption, transfers, and file interactions |
| [server.mjs](server.mjs) | Sessions, authorization, storage, and account management |
| [enrollment.mjs](enrollment.mjs) | Email-bound, single-use registration codes |
| [username-migration.mjs](username-migration.mjs) | Username schema migration |
| [public/register-steps.js](public/register-steps.js) | Step-by-step registration |
| [test/](test/) | Encryption, enrollment, and static-resource checks |
| [scripts/smoke.mjs](scripts/smoke.mjs) | Isolated account and transfer checks |

For encryption review, start with these functions in `public/app.js`:

- `derivePasswordWrappingKey` and `wrapVaultKey`: password derivation and vault-key protection.
- `encryptMetadata`: file metadata encryption.
- `prepareEncryptedUpload`: per-file key generation and upload preparation.
- `chunkIv`, `chunkAad`, and `encryptChunk`: chunk encryption and binding.
- `decodeFileChunk`: reconstruction after decryption.

## Technology

The client uses JavaScript and the browser Web Crypto API. The server uses Node.js, Express, and SQLite, with WebAuthn verification provided by `@simplewebauthn/server`. Dependency versions are recorded in [package-lock.json](package-lock.json).

## About this edition

This is a standalone core-review edition, not a complete production mirror or the native Android client.

Email delivery, commercial payment processing, and private storage-service integrations are not included. Registration uses administrator-issued codes bound to an email string; this does not establish email ownership. Email password resets, new account-deletion requests, and payment entry points are disabled. Local storage is implemented, while some extension interfaces and data structures remain available for inspection.

The application interface currently retains its original Chinese strings. The repository documentation is in English.

You can read the [deployment reference](DEPLOYMENT.md), [verification record](VERIFICATION.md), and [edition notes](CHANGES.md) to understand its scope. Execution instructions are for the rights holder or separately authorized users.

## Questions and security feedback

For general questions, open an Issue describing the relevant file, function, and expected behavior. Do not post passwords, keys, recovery links, databases, or user files. For sensitive findings, contact the [maintainer](https://github.com/yuniaries) to arrange a private reporting channel first.

## Rights and permissions

**Publicly available for review. Not open-source software.**

Copyright (c) 2026 yuniaries. All rights reserved.

You may read the source, retain an unmodified local copy for reading and inspection, and fork it on GitHub as permitted by GitHub's Terms of Service. No additional permission to execute, deploy, modify, redistribute, or use it commercially is granted without separate written authorization. Statutory rights and third-party licenses are unaffected. See [LICENSE](LICENSE).
