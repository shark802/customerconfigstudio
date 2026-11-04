# Local Connector Manager

A local Python utility for reviewing and editing the `LocalConnectors` section of a customer configuration file. It has a Windows-oriented Tkinter interface and a command-line fallback. It uses only the Python standard library, makes no network calls, and creates no scheduled tasks, managed apps, deployments, service restarts or reloads.

**Enabled means an uncommented connector definition in the selected file. It does not mean the connector is running, healthy, receiving files or licensed.** There is no generic `Enabled` property. `DisableSftp4` is a protocol setting, not connector status.

## Included files

- `connector_manager.py` — self-contained application.
- `test_connector_manager.py` — `unittest` regression suite.
- `sample.Customer.config` — tiny, synthetic, secret-free practice configuration.
- `README.md` — this guide.

No actual customer configuration, credentials, private keys, production backups, logs, test scratch directories or caches are included.

## Requirements and launch

Use Python **3.10 or newer**. On Windows, the standard Python installer normally includes Tcl/Tk; include the Tcl/Tk option if installing Python. No `pip install` is needed.

Extract the ZIP into a local folder. Open a terminal in that folder:

```powershell
python connector_manager.py
```

If your Windows installation uses the launcher:

```powershell
py connector_manager.py
```

No arguments opens the GUI. If Tkinter or a graphical display is unavailable, the application explains how to use the CLI instead:

```powershell
python connector_manager.py --help
```

**First practice using `sample.Customer.config` in a secured working folder, not a production configuration.** The practice file has one active filesystem connector and two commented definitions, one of which is an alternative with a repeated identifier.

## GUI workflow

1. Browse to the customer configuration, or enter its full path and click **Open / Reload**. Opening and filtering are read-only; neither creates backups nor changes the config.
2. Review enabled and disabled definitions using Vendor, Transport, Status and Search filters. The table shows a unique definition key and source line; repeated identifiers are separate definitions. Ctrl-click or Shift-click selects multiple rows.
3. Select the actual environment: `dev`, `test`, `sit`, `uat` or `prod`. The default `unknown` cannot be used for edits. Production-looking paths never silently select `prod`.
4. Select rows and click **Stage Enable selected** or **Stage Disable selected**. Nothing is written. Selecting the original state removes that row from the plan. **Clear plan** removes all staged changes.
5. To change between alternative definitions with the same identifier, explicitly stage **Disable** for the currently active definition and **Enable** for the desired definition. Both must appear in the preview. The utility never silently disables a counterpart for you.
6. Read all warnings. A production-labelled source or selected `prod` environment requires **I acknowledge production risk**. Select **I confirm services, editors and deployment/config writers are stopped or coordinated** only after that is actually true.
7. Click **Preview staged changes**. Review the exact target path and each before/after status, transport, direction and definition key. Raw XML and connection properties are deliberately not displayed.
8. Click **Apply reviewed plan…** and confirm the exact target path. Apply first creates and verifies an original backup next to the config, then replaces the original. The completion dialog gives the updated and backup locations.
9. Reopening after success discards old definition keys and requires environment/acknowledgements to be selected again. If the displayed path, staged changes, environment or acknowledgement changes, the previous review is invalidated. A different displayed path must be opened before preview/apply.

An unsupported change is refused with a reason. If Apply fails, inspect the error and current/backup files before trying again; do not keep clicking Apply or blindly restore an old backup.

## CLI: list, plan, then explicitly apply

Inventory is read-only:

```powershell
python connector_manager.py list "C:\SecureConfig\Customer.config"
python connector_manager.py list "C:\SecureConfig\Customer.config" --status disabled --transport SFTP
python connector_manager.py list "C:\SecureConfig\Customer.config" --vendor Bloomberg --search PerSec
```

Use the **definition keys from the current `list` output**, not the identifier alone. The following `L123-...` and `L456-...` values are placeholders; replace them with actual complete keys:

```powershell
python connector_manager.py plan "C:\SecureConfig\Customer.config" --disable "L123-0123456789ab" --enable "L456-abcdef012345" --environment test --out "review.json"
```

`--enable` and `--disable` can each be repeated. The plan command validates the entire result and writes a new JSON plan; it does not modify the configuration. Existing plan files are never overwritten. A plan contains identifiers, definition keys, statuses, source path and hashes, **never raw config or properties**. Treat plans as internal metadata and keep them in a secured local folder. Inspect `review.json` and the printed changes.

Apply is a separate, explicit command:

```powershell
python connector_manager.py apply "C:\SecureConfig\Customer.config" --plan "review.json" --apply --writers-coordinated
```

Omitting `--apply` or `--writers-coordinated` prevents writes. If the file contains production labels/paths or the environment is `prod`, also pass `--ack-production` **when creating the plan and again when applying**:

```powershell
python connector_manager.py plan "C:\SecureConfig\Customer.config" --disable "L123-0123456789ab" --environment prod --ack-production --out "prod-review.json"
python connector_manager.py apply "C:\SecureConfig\Customer.config" --plan "prod-review.json" --apply --writers-coordinated --ack-production
```

Any change to the opened source bytes invalidates the saved plan. Definition keys include identifier/type/direction/source position, so keys can change after an edit; list again and build a new plan. Exit code `0` means success; `2` means refusal or error.

## Safeguards and interpretation

- Recognized section: `configuration/IntegrationServiceCustomerConfigurationSection/LocalConnectors`; active and disabled definitions both use the `LocalConnector` tag.
- Filesystem transports are recognized by `BatchFileSystemInConnector` and `FileSystemOutConnector`. `FtpInConnector` / `FtpOutConnector` with `UseSftp=true` are SFTP; explicit `false` is FTP; missing/unrecognized values are `FTP/Unknown`. Unknown types are displayed as Unknown rather than guessed.
- Vendor groups are a convenience heuristic from the identifier (known prefixes and direction-suffix removal), not an authoritative vendor property. Always verify the exact identifier, type/transport, direction and source line.
- XML comments are parsed as XML fragments, not scanned blindly for text resembling a connector. A single comment may contain multiple definitions and explanatory prose; enabling one splits the enclosing comment and retains the other disabled definitions and prose. Unsupported/ambiguous fragments are warned about and left untouched.
- A connector with an internal XML comment or any `--` cannot safely be enclosed in another XML comment. Disabling it is refused and marked Manual only; use an approved administrative editor for that case. DTDs/entities, malformed XML, missing identifiers, duplicate active identifiers, ambiguous sections and unsupported encodings are refused.
- The utility does not serialize the whole document. It changes only targeted lexical spans and added/removed comment delimiters. Unrelated text, whitespace, existing comments, credentials, BOM, encoding and CRLF/LF bytes are retained. UTF-8, UTF-16 LE/BE, ASCII, Latin-1 and Windows-1252 are supported when they round-trip exactly.
- Source markers such as `SWIBP1`, `Prod`/`Production`, and production-only comments produce generic warnings without exposing paths/properties from inside the config. These markers may coexist with test/dev-labelled key filenames; the tool does **not** infer environment from them. It intentionally errs on the side of requiring acknowledgement for a production-labelled file in a selected nonproduction environment.
- Enabling any ICE/ICE360 identifier with direction `Outbound` is blocked outside selected `prod`, even if production risk was acknowledged. Production-only source safeguards are not stripped or overridden.
- Inventories, previews, plans and error messages omit all connector property values: hosts, usernames, passwords, private-key references and other credentials are not exported. File locations selected by the operator and nonsecret connector identifiers remain visible. Source XML is never logged.

## Backup and write transaction

Apply requires an unchanged source snapshot and the reviewed plan. It rejects symlinks/Windows reparse points (including path components), nonregular files, hard-linked configs, special permission bits and read-only file/directory modes; it never elevates privileges or bypasses access controls.

It creates an exclusive cooperative sidecar lock named `<config>.connector-manager.lock`. This coordinates other instances of this utility. It then creates a collision-resistant, exclusive same-directory backup:

```text
Customer.config.20261104T064754.123456Z.<random-UUID>.bak
```

The backup is flushed/fsynced and its byte hash is verified against the original. On POSIX, the containing directory is also fsynced **before replacement**. A same-directory staging file is created exclusively, flushed/fsynced, reparsed, checked for active-identifier uniqueness and compared to the reviewed result hash. A final source identity/hash check precedes `os.replace`; the resulting file is verified again. The backup is retained and both locations are reported. Temporary staging and this utility's own lock are cleaned up when possible. Failed backup creation/verification prevents replacement. A failed attempt can leave an empty or completed timestamped backup; do not assume every `.bak` is a verified successful transaction merely from its filename.

**Permission/security handling:**

- POSIX backup and staging payloads require enforceable owner-only permissions (`0600`). If the filesystem ignores those permissions, Apply refuses **before writing config payload**. It preserves/verifies source owner and group on the staged replacement and restores the original POSIX mode after the atomic replacement. It refuses source/staging files with extended attributes or POSIX ACLs rather than silently dropping them, and refuses if those attributes cannot be inspected.
- Windows uses native Advapi32 security APIs via standard-library `ctypes` to copy and verify owner SID, group SID, DACL bytes and DACL-protection state on the **empty backup and staging files before any config payload is written**. Failure to read, set or verify this security metadata stops Apply before replacement; absent/null DACLs are refused. Source and replacement DACLs are checked again around replacement. This may require administrative help when the original has ownership/security your account cannot reproduce; do not bypass the refusal.
- **This is not a guarantee of every Windows ACL/security attribute.** SACL auditing, mandatory integrity labels, filesystem-specific metadata, EFS, alternate streams and all sharing/server semantics are not comprehensively preserved/verified. Use an inherited, administrator-approved secured local directory; do not treat this as an enterprise ACL migration or deployment tool. The Windows native write path must be validated with your actual Python/Windows/NTFS/security settings before production use.
- Windows does not have a portable standard-library directory-fsync equivalent here; backup data is flushed before replacement, but full namespace durability across power loss is not guaranteed. Sharing violations or access-denied errors are safe refusals before replacement when possible. If replacement occurred but final permission/security/durability verification failed, the error explicitly says so and **no destructive rollback** is attempted.

**Concurrency limitation:** the cooperative lock and final hash check are not raceproof against unrelated services/editors/deployment tools. There is an unavoidable interval between the last check and replace; an uncooperative writer can write in that interval and its newest content would not be in the earlier backup. You must stop or coordinate **all** writers, then make the explicit GUI/CLI confirmation. This utility does not stop services itself and does not claim safe live concurrent production editing.

## Restore and operations

Backups contain the original plaintext secrets: protect, retain and dispose of them according to your organization's policy. Do not attach backups to tickets or put them in source control.

There is intentionally no one-click/automatic rollback. To restore, stop/coordinate writers, identify the correct timestamped backup, verify its expected hash and XML, preserve a secured copy of the current file, and have an administrator restore using your approved atomic-copy/security-preserving procedure. Recheck owner/group/DACL/mode and the selected environment before any restart. Never overwrite newer concurrent changes blindly.

A leftover lock after a process crash requires manual investigation. Remove it only after confirming that its recorded PID/owner is no longer operating on that file. A stale PID can have been reused; never remove a lock merely because it is old.

## Tests and validation limits

```powershell
python -m unittest -v
```

Tests use only the included synthetic fixture and synthetic payloads. Scratch folders are project-local, uniquely named and cleaned after each test. No tests open production files. Coverage includes comment splitting/prose, repeated identifiers and explicit counterpart changes, protocol interpretation, BOM/CRLF/UTF-16 preservation, production guards, stale plans/files, cooperative locks, backup/replace failures, read-only/symlink refusal and CLI confirmations.

Some hosted/mounted filesystems ignore POSIX mode bits, reject symlink creation or cannot inspect ACL attributes. On such a host, transaction tests explicitly mock **only the private-mode/ACL capability gates for synthetic data**, and real chmod/symlink tests are skipped when unsupported. Separate tests exercise the fail-closed capability checks without that bypass. The application itself has **no bypass flag**. Passing these tests does not establish POSIX security behavior on an incapable mount, nor validate Windows-native ACL calls.

This release was developed/validated in a headless Linux environment. GUI code compiles, but interactive Windows GUI behavior and native Windows security operations were **not executed** there. Test on a safe local copy in your own secured Windows environment before operational use.
