# Backup and restore

A usable ObjectShare backup contains the database, matching object bytes, and the
secrets needed to open them. Keep backups encrypted, access-controlled, and outside
the application checkout and Docker build context. Define how much recent activity
you can lose and how long recovery may take, then measure both during restore drills.

## What to retain together

| Component | What it restores |
| --- | --- |
| Complete PostgreSQL application database | Accounts, roles and moderation, sharing permissions, file metadata, browser-encrypted key vaults, plans, frozen invoice terms, credit ledger, payment deduplication records, token revocations, and encrypted runtime configuration. |
| Filesystem object directory or private object-store snapshot | The bytes identified by each file's object key. Preserve keys and bytes exactly, including ciphertext. The default Compose filesystem volume is `object-data`, mounted at `/var/lib/objectshare`; confirm the active storage configuration before backing up. |
| Bootstrap configuration and deployment secrets | Database connection settings, `OBJECTSHARE_SETTINGS_KEY`, JWT configuration, and any externally managed credentials. Save the effective deployment inputs, including secret-manager references and versions. |
| Encryption keys and metadata | The settings key opens stored operational settings, including configured server-side encryption keys. Client-encrypted files additionally require their database metadata, the owner's wrapped key or encrypted key backup, and the owner's separate encryption passphrase. Operators should not collect users' passphrases. |
| Deployment definition and exact release | Compose/proxy configuration, image digest or binary version, PostgreSQL version, storage location/version identifiers, and a manifest of backup time, checksums, and restore results. |

Dashboard changes are stored in PostgreSQL. Copying an old `config.json` or `.env`
does not capture the current operational configuration. Keep an independent
settings key stable: replacing it makes the stored configuration unreadable.
If an older installation uses the JWT secret as its settings-key fallback, retain
that original value explicitly as the settings key before rotating the JWT secret.
Password reset cannot recover a lost client-encryption passphrase.

## Take a coordinated backup

1. Put the site into maintenance at the ingress and stop new mutations. Stop all
   application replicas and workers before taking the final database/object pair.
   Let outstanding requests finish. For direct uploads, application shutdown alone
   does not stop an already-issued object-store PUT: wait for upload authorizations
   and in-flight transfers to finish or expire, or use a provider-supported snapshot
   and write-control procedure. Record incomplete uploads for later reconciliation.
2. Dump the complete application database with a PostgreSQL client compatible with
   the server. Use a password file or secret-managed connection; avoid passwords in
   command arguments and shell history. This example assumes connection settings
   such as `PGHOST`, `PGPORT`, and `PGUSER` are already configured:

   ```text
   pg_dump --dbname=objectshare --format=custom --file=/secure-backups/objectshare/database.dump
   pg_restore --list /secure-backups/objectshare/database.dump
   ```

   Replace the destination with an existing protected directory. `--file` writes
   the archive directly and avoids binary corruption through shell text pipelines.
   A custom-format dump is a database snapshot; it does not coordinate an external
   object store or include cluster-wide roles and tablespaces. Retain the required
   database-role provisioning separately. See PostgreSQL's [pg_dump documentation](https://www.postgresql.org/docs/18/app-pgdump.html).
3. Snapshot or copy the complete object directory/bucket while writes and retention
   deletion remain stopped. Preserve the original keys, relevant object versions,
   and ownership/permissions needed by the application's container user. Do not
   enable lifecycle deletion on the only backup copy. Check the archive or snapshot
   manifest and compare object counts, sizes, and checksums.
4. Capture the deployment/secret versions from the same maintenance window. Store
   the manifest with the backup, and retain at least one independently protected
   copy. A backup job succeeds only after every required component succeeds.
5. Resume the original application and ingress after verifying the backup set is
   complete. Check readiness, uploads, and background work. A failed backup must be
   reported explicitly; do not silently replace the last known-good recovery set.

For the bundled Compose database, these equivalent database-only commands avoid
streaming a binary archive through the host shell:

```text
docker compose exec -T db pg_dump -U objectshare -d objectshare --format=custom --file=/tmp/objectshare-recovery.dump
docker compose cp db:/tmp/objectshare-recovery.dump /secure-backups/objectshare/database.dump
```

Use a unique temporary filename for overlapping jobs. Verify the copied archive
and securely remove the temporary copy when finished. These commands do not back
up `object-data`, bootstrap secrets, or external buckets. Docker documents the
service/container copy syntax in [Compose cp](https://docs.docker.com/reference/cli/docker/compose/cp/).

## Restore into an isolated environment first

1. Provision a separate database, separate object directory/bucket, and isolated
   application network. Use the backed-up release first. Do not point a restore
   drill at production storage or publish it on the production hostname. Keep
   outbound email, payment/provider calls, and public traffic blocked before any
   restored application process starts: restored settings contain the original
   provider credentials and background jobs may run immediately.
2. Have the database administrator create an empty database owned by the intended
   application role. For example, run the first command as a database administrator
   and the second with the target application role's connection credentials:

   ```text
   createdb --template=template0 --owner=objectshare objectshare_restore
   pg_restore --username=objectshare --dbname=objectshare_restore --no-owner --no-privileges --single-transaction /secure-backups/objectshare/database.dump
   ```

   Do not use `--clean` against a populated installation as a restore drill. The
   example assigns restored objects to the connecting role and omits old grants;
   deliberately recreate any additional application/reporting grants afterward.
   `--single-transaction` fails the restore as a unit. For backups too large for
   that mode, use a planned restore procedure with `--exit-on-error` and discard an
   incomplete destination before retrying. See PostgreSQL's [pg_restore options](https://www.postgresql.org/docs/18/app-pgrestore.html)
   and [SQL dump restoration guidance](https://www.postgresql.org/docs/18/backup-dump.html).
3. Restore object bytes into the isolated storage location and restore the settings
   key through the secret manager. Restore the full database before application
   startup; do not initialize a new empty application and import selected tables.
   Keep network isolation in place while adapting the restored site's public URL,
   storage, email, and gateway settings to the recovery environment. Environment
   storage overrides alone do not replace the runtime settings restored from the
   database. The default filesystem path can be preserved inside a separate volume.
4. Start the backed-up application version against the restored database and
   isolated objects. Check startup/migration logs and `/health/ready`. Verify an
   administrator can access settings, an ordinary user can access their files, and
   unrelated users cannot read private files. Use a test owner's retained key and
   passphrase to download and decrypt an existing encrypted file. Inspect a paid
   invoice and its PDF, balance, and plan terms. Test both signed-in and guest flows
   used by the installation. Run database `ANALYZE` after restoration.
5. Record the archive identity, restored row/object counts, checksums, application
   version, time taken, and actual browser/provider checks. A readable archive or a
   healthy database alone does not prove application recovery.

## Return to service after an actual recovery

Reconcile activity after the backup time before reopening the site. External
payment acceptance is not rolled back with PostgreSQL: compare provider records
with restored invoices, credits, and payment events before retrying payments or
replaying webhooks. Review queued email to avoid duplicate delivery. Reconcile
objects created/deleted after the snapshot and incomplete upload reservations.

Database rollback can restore old password hashes, moderation/access settings, and
token-revocation state. Rotate the JWT secret on every replica to invalidate
previous browser/API JWTs, preserving the independent settings key as described
above. Reapply required post-backup security changes and investigate any missing
revocations before enabling login. Start one application instance, verify the
recovered workflows, then enable other replicas and reopen the ingress. Keep the
original recovery set until the replacement backup has itself passed restoration.

## Verification performed in this workspace

A local PostgreSQL 18 drill stopped the disposable application, created a custom
dump, copied its filesystem objects, and restored into a new database. All 15
application tables matched canonical row fingerprints; all three copied objects
matched SHA-256 hashes. The restored runtime settings opened with the saved key
and rejected an incorrect key. An existing private client-encrypted fixture
authenticated and decrypted to its expected plaintext using the restored vault
and metadata. A paid invoice generated a PDF from restored records. The original
preview then restarted and returned HTTP 200 from its readiness endpoint.

The restored application subsequently started against that separate database and
copied filesystem storage, with external providers confirmed disabled and a fresh
JWT signing secret. HTTP checks verified readiness, login with an existing test
account, Files/Billing/Invoices pages, and an owner-authorized private download
that decrypted to the expected plaintext. Guest file/download access and ordinary
user access to administrator routes were denied. The restored JWT was rejected by
the original preview. The regenerated one-page paid invoice was rendered and
visually inspected: issuer, invoice identifier, purchase, amount, payment details,
and footer were readable without clipping or overlap. The extra restore-test
application was stopped after these checks.

This is local recovery evidence, not a completed deployment restore. The restored
application's browser workflows, Docker volume ownership, remote bucket snapshots,
mailbox delivery, payment reconciliation, and production recovery time remain
deployment checks. Track them
in [production readiness](production-readiness.md).
