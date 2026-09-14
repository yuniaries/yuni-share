# Source Verification

## Snapshot identity

The included application files were read from the running `yuni-share-app` container on September 14, 2026.

Container image label: `yuni-share-app:share-style-integrity-20260913-r1`.

The files listed in [SOURCE-SHA256.txt](SOURCE-SHA256.txt) were compared with SHA-256 values obtained directly from the running container. Their bytes matched at capture and local verification time. The list covers the included application files, not repository documentation or all infrastructure.

## Exclusions

Environment files, deployment secrets, user data, databases, installed dependency directories, APK distributions, update manifests, and historical backups are not published.

External email, payment, and storage services run separately and are not part of this application source snapshot. Calls to those services remain in the code.

## What the comparison means

You can identify the exact application-file snapshot disclosed here and compare its files with the published hashes. No enrollment substitute, integration stub, or local-storage patch from the earlier review edition remains in these runtime files.

The date matters: later deployments may change. The hash inventory records this comparison; it is not a third-party attestation, reproducible-build result, or independent security audit.

## Earlier tests

Earlier verification results in Git history refer to the previous adapted edition. They are not carried forward as runtime acceptance results for this snapshot. The restored snapshot has not undergone a new complete browser, authenticator, payment, or transfer test in this publication step.
