# Yuni Share

Your files, protected before they leave your browser.

Yuni Share provides personal file storage with client-side encryption. Your browser encrypts file contents before upload and decrypts them when you download. File names, paths, and per-file keys are protected within encrypted metadata.

This repository contains the application source used by Yuni Share, excluding environment files, deployment secrets, user data, and non-source distribution artifacts. The included application files match the running application snapshot checked on **September 14, 2026**. See [Source Verification](VERIFICATION.md) for the scope and file hashes.

## What you can explore

- **File protection:** independent random file keys and AES-GCM chunk encryption.
- **Private metadata:** encrypted file names, paths, and per-file keys.
- **File management:** uploads, downloads, previews, search, and folders.
- **Account access:** registration, sign-in, sessions, username changes, and Web Passkey flows.
- **Transfers and storage:** chunk handling, completion checks, local and external storage paths, quotas, and administrative interfaces.

## How your files are protected

Your browser generates a vault key. Your separate encryption password is processed with PBKDF2-SHA256 to derive a key that protects it. Your sign-in password and encryption password serve different purposes.

Each upload receives a random 256-bit file key and a file nonce. Chunk encryption binds content to the upload identifier and chunk index using authenticated data. The client verifies and decrypts downloaded chunks before reconstructing the file.

Format version 2 can apply lossless gzip compression before encryption when supported and beneficial. It does not perform lossy image or video transcoding.

File content and sensitive metadata are encrypted, but account and storage information such as email addresses, timestamps, sizes, and category hints remains visible to the server. Avatars are outside file encryption. Read [Your Files and Privacy](SECURITY.md) for details.

## Find your way around the code

| Location | What you can inspect |
| --- | --- |
| [public/app.js](public/app.js) | Client-side encryption, key handling, and file interactions |
| [server.mjs](server.mjs) | Authentication, file permissions, account workflows, and storage |
| [membership-expiry.mjs](membership-expiry.mjs) | Membership reminder scheduling and notification logic |
| [username-migration.mjs](username-migration.mjs) | Username schema migration |
| [public/register-steps.js](public/register-steps.js) | Registration steps |
| [public/](public/) | Web pages, scripts, styles, and referenced assets |

For encryption review, look for `derivePasswordWrappingKey`, `wrapVaultKey`, `encryptMetadata`, `prepareEncryptedUpload`, `chunkIv`, `chunkAad`, and `encryptChunk`.

## Repository scope

Application behavior has not been replaced with mock registration or disabled integration stubs. The original email, payment, and storage call paths are included. Their separately operated services, credentials, environment settings, databases, uploads, APKs, and historical backups are not included.

This is the Web application source, not the native Android source. Interface strings retain their production language. Supporting repository documentation is in English.

The recorded match applies to the dated snapshot; later live deployments may differ. Publication makes the code available for inspection and does not itself constitute an independent security audit.

## Technical reference

The application uses JavaScript, Web Crypto, Node.js, Express, SQLite, and WebAuthn. Exact dependency resolutions appear in [package-lock.json](package-lock.json).

For environment requirements, read [Deployment Reference](DEPLOYMENT.md). For snapshot provenance and exclusions, read [Edition History](CHANGES.md).

## Questions and security feedback

General questions are welcome in Issues. Describe the relevant file, function, and expected behavior. For sensitive findings, contact the [maintainer](https://github.com/yuniaries) to arrange a private channel first. Never post real passwords, keys, recovery links, databases, or user files.

## Rights and permissions

**Publicly available for review. Not open-source software.**

Copyright (c) 2026 yuniaries. All rights reserved.

You may read the source, retain an unmodified local copy for reading and inspection, and fork it on GitHub as permitted by GitHub's Terms of Service. No additional permission to execute, deploy, modify, redistribute, or use it commercially is granted without separate written authorization. Statutory rights and third-party licenses are unaffected. See [LICENSE](LICENSE).
