# Patched third-party crates

Crates copied here are used through `[patch.crates-io]` in `rust/Cargo.toml`, because the
published version has a defect that the port cannot work around. Each one stays as close to
the published crate as possible, so that it can be dropped as soon as a fixed release exists.
See ADR 0016 (not published), "Faisabilité".

## `ldap3` 0.12.1 (MIT or Apache-2.0, Ivan Nejgebauer)

Source: crates.io `ldap3-0.12.1`. Kept: `src/`, `Cargo.toml`, licences, README, changelog.
Removed: `examples/`, `data/`, `Cargo.lock`, the `[[example]]` and `[dev-dependencies]` tables
of `Cargo.toml` (not built from here).

Changes, all in `ldap3-sasl.patch` (diff against the published sources):

1. **SASL confidentiality layer, receiving side** (`src/protocol.rs`, `src/conn.rs`). The
   published decoder assumes that one SASL buffer holds exactly one LDAP message: extra
   messages in a buffer are dropped, and a message spanning several buffers is lost. Samba
   does both, so a paged search over a GSSAPI-sealed connection stops after a few pages with
   `EndOfStream`. The decoder now accumulates the unwrapped plaintext in its own buffer
   (`LdapCodec::plain`), returns messages from it one at a time, and unwraps another SASL
   buffer only when a message is incomplete; a SASL buffer received in part waits for the
   rest instead of failing with "invalid SASL buffer".
2. **Security layer check** (`src/ldap.rs`). `buf[0] | needed_layer == 0` (always false) is
   now `buf[0] & needed_layer == 0`: a server that does not offer the needed layer fails the
   bind instead of being wrapped anyway. No effect on Active Directory, which offers all three.

Measured on the lab (Samba 4.22, Windows Server 2025): 22 016 entries in pages of 1 000 over a
sealed connection, identical to python-ldap.

Upstream (2026-10-15): change 1 is already proposed by someone else in
<https://github.com/inejge/ldap3/pull/160>, with the same design and unit tests; a comment there
adds the Samba case. Change 2 is <https://github.com/inejge/ldap3/pull/161>. The last upstream
commit dates from September 2025 and older pull requests are still unanswered.

## `libgssapi` 0.9.1 (MIT, Eric Stokes)

Source: crates.io `libgssapi-0.9.1`. Kept: `src/`, `Cargo.toml`, README. Removed: `examples/`,
`Cargo.lock`, `.cargo_vcs_info.json`, `.gitignore`, `Cargo.toml.orig`, the `[[example]]` and
`[dev-dependencies]` tables of `Cargo.toml`.

Change, in `libgssapi-session-key.patch` (diff against the published sources):
`ClientCtx::inquire_sec_context_by_oid`, a safe wrapper of `gss_inquire_sec_context_by_oid`
(`src/context.rs`, about forty lines in the style of the crate's other calls). SMB signs and
encrypts with keys derived from the session key of the Kerberos context
(`GSS_C_INQ_SSPI_SESSION_KEY`), which the published crate does not expose; the `unsafe` call
stays here, out of the crates of the project, which forbid it (ADR 0017, § 2). The same crate
is used by `ldap3` through `cross-krb5`: nothing else changes for it.

Upstream (2026-10-15): <https://github.com/estokes/libgssapi/pull/40>, written against 0.11.0,
where the method is `SecurityContext::inquire_sec_context_by_oid` (client and server contexts)
rather than an inherent method of `ClientCtx`. Dropping this copy will therefore also mean
moving to 0.11 and importing the trait.
