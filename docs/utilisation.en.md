# Using Calinda

Calinda manages an Active Directory or Samba domain from GNOME, without a Windows computer:
accounts, groups, organizational units, DNS and Group Policy. This guide covers version 1.2.
Up to version 1.1, the application was called Annuaire.
Version française : [utilisation.md](utilisation.md).

## Installing

Calinda is distributed as an RPM for Fedora 44 and later (x86_64). The package depends only on
Fedora packages: GTK 4, libadwaita, and the Kerberos, OpenSSL and SQLite libraries that are
already on the system. There is no repository yet; install the file you received, or the one you
built yourself (README, section “Construire le RPM”):

```sh
sudo dnf install ./calinda-1.2.0-1.fc44.x86_64.rpm
```

The application appears as “Calinda” in the application menu; from a terminal, the command is
`calinda`. To uninstall it: `sudo dnf remove calinda`.

The computer must be able to resolve the domain's DNS, since domain controllers are found
through their SRV records, and its clock must be within a few minutes of the controllers'.

Group Policy is read and written on the SYSVOL share over encrypted SMB 3, which Samba and
Windows Server 2012 or later support. Domain controllers that only speak SMB 2 (Windows Server
2008 R2 and earlier) are supported for the SYSVOL through a domain profile option, “Allow SMB 2
with signing only (older controllers)”, off by default. With it, SYSVOL content travels
unencrypted but authenticated by Kerberos and signed against modification; SMB 3 stays
encrypted in every case. Without it, the application refuses these controllers and names the
option to enable.

## Kerberos

Calinda neither asks for nor stores any logon password: it uses the session's Kerberos ticket.
There are two ways to get that ticket.

- In the application, on the start page, “Get a Ticket…”: enter the user name alone (the realm
  is then the chosen domain's) or as `user@REALM`, then the password. The password is used only
  to request the ticket from the controller; it is neither stored nor logged.
- From a terminal: `kinit administrator@EXAMPLE.LOCAL`, then `klist` to check.

On Fedora, the credential cache is the session's (`KCM:`), shared with other tools. If `kinit`
cannot find the controller, check that `/etc/krb5.conf` contains `dns_lookup_kdc = true`. If
binding fails with the message “Kerberos does not know the LDAP service”, add `rdns = false` to
the `[libdefaults]` section of the same file.

Writes are made with the rights of the account that holds the ticket. An account without
administrative rights can read most of the directory; anything it cannot read is reported as
such, never shown as missing.

## First profile

On the start page, “Add a domain” (in the header bar, below the list, or Ctrl+N) opens the
profile form:

- **DNS name of the domain** (`example.local`): when you confirm it, the controllers are looked
  up in DNS and listed.
- **Preferred controller**, used for reading, and **write controller**, by default the PDC
  emulator, which is the one the Windows consoles use.
- **Security**: sealed GSSAPI by default, which encrypts everything without a certificate; LDAPS
  or StartTLS if the domain requires it, with the certificate of the domain's certification
  authority, whose fingerprint you compare with the one the controller shows. “Allow SMB 2
  with signing only” is only meant for older controllers (see “Installing”).
- **Read-only**: nothing can be written to the directory from this profile. A new profile stays
  read-only until you edit it; this is deliberate, so that a first look at a production domain
  carries no risk.
- **Local copy**: the computer keeps the names, accounts and memberships that were read (never a
  secret), so that the next opening displays them immediately; the copy is updated with deltas.
  It is not encrypted: for a customer's domain, use an encrypted disk. Turning it off erases it.

A profile is edited or deleted from the menu on its row. “Erase the Local Copy” deletes the
copy; it is rebuilt on the next opening.

## The windows

**Main window.** The domain tree is on the left; system containers only appear with “Advanced
Features”, in the main menu. The objects of the selected container are on the right, displayed
as they are read, with the columns chosen in the main menu.

Search (Ctrl+F) covers the whole domain: name, logon name, email address and description, with
filters by type and state. Ready-made queries find accounts inactive for N days, disabled or
locked out accounts, passwords that never expire, administrators through recursive membership
and conflicting objects; you can add your own.

The “New” button creates a user, a group or an organizational unit. The actions menu works on
the selection: enable, disable, unlock, reset the password, move, rename (F2), delete (Delete),
protect an OU from accidental deletion.

The bottom of the sidebar leads to the domain's other windows, each with its shortcut: DNS
(Ctrl+D), DNS Health (Shift+Ctrl+D), Group Policy (Ctrl+G), Password Policies (Ctrl+M) and
Change History (Ctrl+H). They are also in the main menu.

**Properties.** Enter or a double click opens the object's properties: the general, account,
members or “Member Of” tabs and, depending on the object:

- “Security”: owner, permissions described in plain sentences, auditing, SDDL; “Delegate…” on
  an OU; in the “ACEs and SDDL” view, “Add…” writes an entry typed in SDDL, conditional or not
  (see below);
- “Attributes”: every attribute the schema allows, editable when the account has the right;
  “Auxiliary Classes…” adds or removes an auxiliary class offered by the schema, with the
  attributes it brings;
- “Policy”: the GPOs applied to the account or computer, by precedence, and those that do not
  apply, with the reason. For a computer, the tab shows its loopback processing; for a user, it
  computes the policy on the computer you enter, loopback processing included (merge or
  replace).

Changes accumulate in the properties and are sent together with “Apply…”.

**Common preview.** Every write, whatever the window, goes through the same preview, which
shows each object, attribute or file before and after. “Apply” first checks that nothing has
changed since the preview, writes to the write controller, then reads the result back to
confirm it. Permissions added or removed are spelled out, with the trustee's name, and shown in
SDDL; a conditional permission (dynamic access control) appears with its condition. A change
that affects several objects is all or nothing: if it fails, whatever was already written is
undone.

**History.** Ctrl+H, or “Change History”, opens the local log of every write made from this
computer (`$XDG_STATE_HOME/calinda/changes.jsonl`), with “Undo this change”. Ctrl+Z offers to
undo the last change, through the preview; pressing Ctrl+Z again offers the one before, even on
the same object, as long as nobody else has changed it in the meantime. A deletion can only be
undone by recreating a new object, with a new SID and GUID; the preview says so beforehand.

**DNS.** Ctrl+D, or “DNS”, shows the directory-integrated zones, their names and records, and
each zone's settings. Ctrl+N adds a record (A, AAAA, CNAME, PTR, MX, SRV, TXT; for an A record,
the reverse pointer is offered), Enter or F2 edits it, Delete removes it; the SOA serial number
is updated accordingly. “DNS Health” (Ctrl+D in the DNS window, Shift+Ctrl+D from the main
window) looks for common problems: name servers and DC locators that no longer exist, retired
machines, inconsistent pointers, records that are not refreshed, old tombstones. It offers to
fix them through the preview.

**Group Policy.** Ctrl+G, or “Group Policy”, lists all GPOs, then the domain and its OUs with
their linked GPOs, in link order. A GPO's details give its status, its versions in the
directory and in SYSVOL (they must match), its links and its filtering; an alert reports any
divergence, including between the controllers' copies of SYSVOL.

The window menu creates a GPO (Ctrl+N) or links an existing one (Ctrl+L). On a link, it removes
it (Delete), moves it up or down (Alt+Up, Alt+Down), enables it (Ctrl+D) or enforces it
(Ctrl+E). It also blocks inheritance on an OU (Ctrl+B), sets security filtering (Ctrl+I), backs
up a GPO (Ctrl+S) and restores it (Ctrl+O). When there are any, “Inconsistencies” shows SYSVOL
folders without a GPO and GPOs without a folder. Delete on an orphaned folder removes it;
“Remove Folders Without a GPO From SYSVOL…”, in the menu, removes them all. Both go through the
preview.

**GPO contents.** In the Group Policy window, Ctrl+M or “Edit Contents…” on a GPO opens its
editor, which is laid out like the GPMC's. Computer Configuration and User Configuration, with
their policies and preferences, are on the left; the page of the selected node is on the right.

“Administrative Templates” shows the categories of the domain's central store
(`SYSVOL\<domain>\Policies\PolicyDefinitions`), with texts in the session language, or in
English otherwise. A category shows its subfolders and its policies, each with its state: Not
Configured, Enabled or Disabled. Ctrl+F searches every policy of the part (title, explanation,
registry key) and Enter opens the first match; Shift+Ctrl+F shows configured settings only; “All
Settings” lists them all.

Enter on a policy opens it: its state, the template's options, checked as you type (bounds,
length, required values), “Supported on”, the registry key and the explanation. “Apply”
(Ctrl+Enter) adds the setting to the pending changes, listed at the bottom of the window.
Ctrl+S presents them in the common preview, in plain words (“Policy “…”: Enabled; option = 3”)
and file by file, then writes them: `Registry.pol`, the GPO version in the directory and in
`GPT.INI`, and the declared extensions. Ctrl+Z undoes the last write.

`Registry.pol` values that no template describes are shown under “Extra Registry Settings” and
kept as they are; “Registry (raw)” shows the whole file. In both views, Ctrl+N or the “+” button
adds an entry. You choose the part, the action (set the value, delete the value, delete all the
key's values), the key without the hive, the name, the type (REG_SZ, REG_EXPAND_SZ, REG_DWORD,
REG_QWORD, REG_MULTI_SZ, REG_BINARY) and the data, checked as you type: an integer in decimal or
hexadecimal and within its bounds, bytes in hexadecimal, one string per line. Enter on an entry
edits it; Delete or the trash button removes it. Everything goes through the same draft and the
same preview.

Without a central store, the editor says so and shows only the raw registry. The first opening
reads the store (a few seconds for 200 templates); later openings load it from the local cache
(`$XDG_CACHE_HOME/calinda/modeles`).

**Preferences.** In a GPO's editor, each part's “Preferences” branch contains, as in the GPMC,
“Drive Maps” (user part), “Shortcuts” and “Registry” under “Windows Settings”, and “Printers”
(shared printers, user part) under “Control Panel Settings”. Each page lists the items in the
order the computer processes them: Ctrl+N adds one, Enter edits it, Delete removes it, Alt+Up
and Alt+Down move it.

Each item's dialog checks the input as you type: `\\server\share` path, drive letter, registry
key and data according to the type. Its “Targeting” tab restricts the item to a security group,
an OU, a computer name or a user, with negation (“is not”) and a choice between “AND” and “OR”;
other filters set by the GPMC are left as they are. The common options are those of the
console. Nothing is written before “Save…” (Ctrl+S), which goes through the common preview;
items created by the GPMC are kept byte for byte. A password stored in a preference (MS14-025,
readable by any domain user) is flagged by a banner; the tool never writes one, and editing the
item removes it.

**Security settings of a GPO.** Ctrl+T on a GPO, or “Security Settings…”, opens the password
policy, the account lockout policy, user rights assignment and restricted groups, all stored in
the `GptTmpl.inf` file of the computer part. Each setting has its “Define this policy setting”
switch, its value and an explanation; the value the domain currently enforces is shown next to
it.

**A password policy applies to domain accounts only when it comes from a GPO linked to the root
of the domain**, in practice the Default Domain Policy. Linked to an OU, it only governs the
computers' local accounts, and the page says so. To apply a policy to some users only, the
domain offers fine-grained password policies (PSOs), described below. On a Samba domain, Samba
does not apply the GPO itself: when saving, the tool also writes the values to the domain
object, in the same write, as `samba-tool domain passwordsettings set` would. On Windows, the
PDC emulator takes care of it.

User rights and restricted groups designate accounts through a search like the one in the
Delegation of Control Wizard, or among built-in groups (Administrators, Network Service…).
“Save…” (Ctrl+S) leads to the common preview; Ctrl+Z in the main window undoes the write,
including the domain object.

**Password Policies.** Ctrl+M in the main window, or “Password Policies”, shows the domain
policy (the one from the Default Domain Policy), then the fine-grained password policies (PSOs)
by precedence, each with its settings and the accounts it applies to. A PSO replaces the domain
policy for the accounts and global security groups it lists. Among several PSOs, the one with
the lowest precedence value wins, and a PSO linked directly to the account wins over those of
its groups.

Ctrl+N creates a PSO, whose settings start from the domain policy; Enter or the pencil button
edits it, the trash button deletes it. The dialog uses the GPMC labels. Durations are typed in
plain words (“42 d”, “1 d 12 h”, “30 min”, “90 s”, “never”; French units are accepted too). A
bare number counts as days for password ages and as minutes for lockout. An invalid or
inconsistent value, such as a minimum age greater than the maximum age or a counter reset longer
than the lockout duration, is flagged as you type and blocks “Continue…”.

Accounts and groups are found as in the delegation wizard; a group that is not a global
security group, or a computer, is flagged as having no effect. Everything goes through the
common preview, and Ctrl+Z undoes the operation (a deleted PSO is recreated with the accounts
and groups it applies to). A PSO created by `samba-tool` or PowerShell is read without loss, and
an edit writes only what changes. A user's properties show, under “Status”, the password policy
that applies to the user (`msDS-ResultantPSO`, computed by the domain controller).

**Access control entry in SDDL.** In the “Security” tab of the properties, “ACEs and SDDL” view,
“Add…” opens an input field for an allow or deny entry, simple, object or conditional, in the
Samba or Windows form, for example `(XA;;WP;;;AU;(Member_of {SID(S-1-5-21-…-1105)}))`. The input
is parsed on every keystroke: the dialog shows the entry in plain words (“Authenticated Users
can write all properties on this object, if the account is a member of …”, with groups named
from the directory) and the form that will be written, or the error.

A condition that cites `SID(DA)`, `SID(DU)` or another domain-relative abbreviation is written
with the full SID, as Windows does: Samba 4.22 cannot read these abbreviations back in a
condition and crashes, as a remark in the dialog points out. Auditing and resource attributes,
which belong in the SACL, cannot be added here. The entry takes its place in canonical order;
the common preview shows it and Ctrl+Z removes it.

**Shortcuts.** Ctrl+? shows every keyboard shortcut; everything can be done without a mouse.

## Language

The interface follows the session's language: French if the session is in French, English
otherwise. To start the application in English from a French session:

```sh
LANGUAGE=en calinda
```
