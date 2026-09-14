# Edition History

## Production-source snapshot — September 14, 2026

The current application files were copied from the running Yuni Share container and checked against SHA-256 hashes obtained from that container. They retain production application logic, including registration, notifications, payment integration, and storage paths.

Environment files, secrets, user data, installed dependencies, APK distributions, update manifests, and historical backups are excluded. Repository documentation and the rights notice are publication materials, not runtime files.

## Earlier review edition

Earlier commits contained a standalone adaptation with administrator-issued registration codes, unavailable integration stubs, local-storage fixes, and adapted assets. Those changes have been replaced with the corresponding production files in the current snapshot.

Tests and deployment scaffolding specific to that adaptation were removed. Their earlier results should not be interpreted as test results for the restored production snapshot. Prior commits remain in Git history for transparency.

See [Source Verification](VERIFICATION.md) for the current file inventory.
