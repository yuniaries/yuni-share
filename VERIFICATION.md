# Verification Record

This page helps you distinguish tested behavior from areas that still require assessment.

## Recorded checks — September 14, 2026

Checks were performed against an isolated local edition, not the live service.

- Docker image build completed on Linux amd64 with Node.js 22 and locked dependencies installed through `npm ci`.
- All four automated tests passed inside the image.
- Local script and stylesheet references existed, and declared SHA-384 integrity values matched their assets.
- Tests exercised the actual frontend chunk functions: encryption/decryption, incorrect authenticated data, modified ciphertext, and rejection when a different password-derived key was used.
- Enrollment tests covered email binding, single use, five-attempt lockout, and an explicit unavailable response for code delivery.
- An isolated smoke test covered registration, session access, two-chunk compressed-format upload, completion, byte-for-byte ciphertext download comparison, logout, unauthenticated rejection, subsequent sign-in, and HTTP 501 responses for unavailable integrations.
- The publication directory was checked for APKs, databases, user ciphertext, environment secrets, and email transports. Pattern checks found no matching common private-key/token markers or original site addresses. Pattern scanning is not a guarantee that every possible issue has been detected.

## What these checks do not establish

They are not a comprehensive security audit, penetration test, dependency vulnerability assessment, or formal cryptographic proof.

Recorded testing does not cover full browser visual acceptance, physical Passkeys, every preview/editing path, long-running concurrent transfers, or native Windows npm installation. External storage, email, payments, and Android are outside this edition.

These results do not establish that the live service runs identical code.

## Reproducing the checks

Execution requires ownership or separate written authorization under [LICENSE](LICENSE).

```sh
docker compose build
docker compose run --rm share npm test
docker compose run --rm share node scripts/smoke.mjs
```

The smoke script uses a temporary data directory and port 18292 inside the container. It does not reuse an existing database. Do not adapt it to target a live production service.

## Documentation language

The public documentation is written in English. Application interface strings remain in their original language; documentation changes do not constitute a new functional test run.
