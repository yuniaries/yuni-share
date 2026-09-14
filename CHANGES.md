# Edition Notes

This page explains what you can expect from the public review edition and how its scope differs from the full service.

## Included

The edition retains core client-side encryption, file management, account authorization, and local storage logic. Supporting tests and configuration examples make these components easier to inspect.

## External services

- Email delivery and notification templates are excluded. Notification extension points return an unavailable result.
- Payment callbacks and order-processing implementations are excluded; corresponding entry points return HTTP 501.
- The private storage-service transport is excluded. This edition uses local storage; retained remote-storage branches cannot be enabled.
- APK packages, update manifests, historical backups, production configuration, and user data are excluded.

Quota models, subscription structures, and some extension interfaces remain so you can understand their relationship to file accounting and authorization.

## Accounts

Registration uses an administrator-issued, email-bound, single-use code with an expiry and an attempt limit. It does not establish mailbox ownership.

Email password resets and new account-deletion requests are disabled. Recovery validation remains available for inspection, without email delivery. This edition is not intended to accept an existing production database.

## Presentation

Production domain references, Android certificate associations, and the personal avatar were removed. A simple SVG provides the default brand image. Policy pages are placeholders for separately authorized deployments.

## Local-storage fixes

Two changes support complete transfers through the local storage implementation:

- The completion INSERT now has 17 placeholders for its 17 columns.
- Recording another chunk preserves already completed chunk sizes when other entries remain null, rather than resetting the partial record.

The verification record describes the isolated transfer checks.

## Publication scope

This is a derived review edition, not evidence of production-code equivalence. Documentation and publication permissions are described in [README.md](README.md) and [LICENSE](LICENSE).
