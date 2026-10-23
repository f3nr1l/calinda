// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Security » tab of a file or folder of a share (ADR 0023 § 5, J8.4), as the one of
//! Windows, and the dialog of one permission entry. Structures in `dialogue-securite-ntfs.blp`
//! and `dialogue-entree-ntfs.blp`; texts in `share_views`; inheritance in `annuaire_core::ntfs`.
//!
//! The element and its ancestors are read in one batch of compounds: the ancestors say where
//! an inherited entry comes from and give the entries of the parent when inheritance is turned
//! on again. SIDs are named by the directory, then those it does not know (accounts and groups
//! local to the server) by the server itself (`lsarpc`). What is read is the « before » of the
//! changeset, compared with the server before the write (ADR 0006).
//!
//! « Continue » writes the descriptor as `SetSecurityInfo` does (`ntfs::composed`: canonical
//! order, automatic inheritance asked). If what the children of a folder inherit changes, or
//! if « Replace » is on, the descendants are counted and a confirmation of its own says how
//! many elements will be examined and where their descriptors are saved, before the common
//! preview, which then holds a second operation: the propagation (`PropagateInheritance`).
//!
//! J8.7: the owner is changed (« Change »: myself, Administrators, an account or group of the
//! directory) and, for a folder, replaced below; the auditing entries (SACL) are read with the
//! rest when the account holds SeSecurityPrivilege, shown, edited and propagated as the
//! permissions, and said missing otherwise (the tab stays usable).

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Sid;
use annuaire_codecs::sd::{Ace, SecurityDescriptor};
use annuaire_core::cache::Source;
use annuaire_core::changes::{Changeset, Operation, Report};
use annuaire_core::ntfs;
use annuaire_core::propagation;
use annuaire_core::security::SidName;
use annuaire_core::source::Item;
use annuaire_core::sysvol::{self, INFO_OGD, INFO_SACL};
use gtk::{gio, glib};

use crate::delegation::{MAX_RESULTS, candidate_row, object_sid};
use crate::errors;
use crate::feed::Feed;
use crate::folders::{ShareFiles, file_problem};
use crate::gpo_dialogs::count_text;
use crate::i18n::{fill, tr, tr_n};
use crate::scope::TemplateScope;
use crate::security_views as sv;
use crate::share_views::{self as shv, FileLevel, Names};
use crate::sheet_views::{self as sheet, ElementView};
use crate::writes::{self, Options};

fn empty(list: &gtk::ListBox) {
    while let Some(child) = list.row_at_index(0) {
        list.remove(&child);
    }
}

/// NTSTATUS of a SACL the account may not read (J8.7).
const PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const ACCESS_DENIED: u32 = 0xC000_0022;

/// The bits of the control that go with the SACL.
const SACL_BITS: u16 = annuaire_codecs::sd::SE_SACL_PRESENT
    | annuaire_codecs::sd::SE_SACL_PROTECTED
    | annuaire_codecs::sd::SE_SACL_AUTO_INHERITED
    | annuaire_codecs::sd::SE_SACL_AUTO_INHERIT_REQ;

/// Why the auditing entries are not shown: the privilege the server asks.
fn audit_refusal(status: Option<u32>) -> String {
    match status {
        Some(PRIVILEGE_NOT_HELD) => tr(
            "The auditing entries cannot be read: the account does not hold the “Manage auditing and security log” privilege (SeSecurityPrivilege) on the server. The permissions and the owner can still be changed.",
        ),
        Some(code) => fill(
            &tr(
                "The server refuses the auditing entries to this account (0x{statut:08X}). The permissions and the owner can still be changed.",
            ),
            &[("statut:08X", &format!("{code:08X}"))],
        ),
        None => tr("The server did not give the auditing entries."),
    }
}

/// The ancestors of `path`, the parent first, up to the root of the share (« »).
fn ancestors(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = path.to_owned();
    while !current.is_empty() {
        current = sysvol::parent(&current).to_owned();
        out.push(current.clone());
    }
    out
}

/// What is read for the tab: the element, its ancestors (`None` where unreadable), the names.
struct Reading {
    bytes: Vec<u8>,
    descriptor: SecurityDescriptor,
    ancestors: Vec<Option<SecurityDescriptor>>,
    names: Names,
    /// Why the SACL could not be read (NTSTATUS), if it could not (J8.7).
    audit_refused: Option<u32>,
}

/// The SIDs of a descriptor: owner, group, ACEs.
fn sids_of(d: &SecurityDescriptor) -> Vec<Sid> {
    d.owner
        .iter()
        .chain(d.group.iter())
        .copied()
        .chain(ntfs::dacl_of(d).iter().filter_map(Ace::sid))
        .chain(ntfs::sacl_of(d).iter().filter_map(Ace::sid))
        .collect()
}

// --- The « Security » tab -----------------------------------------------------------------------

mod imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-securite-ntfs.ui")]
    pub struct FileSecurityDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub owner_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub owner_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub owner_replace_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub inheritance_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub inheritance_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub entries_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub audit_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub audit_unavailable: TemplateChild<gtk::Label>,
        #[template_child]
        pub audit_inheritance_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub audit_inheritance_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub audit_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub audit_none: TemplateChild<gtk::Label>,
        #[template_child]
        pub kind_row: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub audit_replace_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub nobody_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub add_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub creator_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub principal_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub children_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub replace_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub problems_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub problems: TemplateChild<gtk::Label>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub connection: RefCell<Option<Arc<annuaire_core::connection::Connection>>>,
        pub files: OnceCell<ShareFiles>,
        pub path: RefCell<String>,
        pub folder: Cell<bool>,
        pub read_only: Cell<bool>,
        /// The descriptor read, as read (the « before ») and decoded.
        pub before: RefCell<Option<(Vec<u8>, SecurityDescriptor)>>,
        pub ancestors: RefCell<Vec<Option<SecurityDescriptor>>>,
        pub explicit: RefCell<Vec<Ace>>,
        pub inherited: RefCell<Vec<Ace>>,
        pub protected: Cell<bool>,
        /// The SACL read (J8.7): false when the account may not read it.
        pub audit: Cell<bool>,
        pub audit_explicit: RefCell<Vec<Ace>>,
        pub audit_inherited: RefCell<Vec<Ace>>,
        pub audit_protected: Cell<bool>,
        pub names: RefCell<Names>,
        pub search: RefCell<Option<Rc<Feed>>>,
        pub received: RefCell<Vec<(ElementView, Option<Sid>)>>,
        pub after: RefCell<Option<SecurityDescriptor>>,
        /// The owner chosen (« Change »), if it is not the one read.
        pub owner: Cell<Option<Sid>>,
        /// The confirmation of a propagation, while it is shown.
        pub confirmation: RefCell<Option<(adw::AlertDialog, usize)>>,
    }

    impl std::fmt::Debug for FileSecurityDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FileSecurityDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for FileSecurityDialog {
        const NAME: &'static str = "AnnuaireDialogueSecuriteNtfs";
        type Type = super::FileSecurityDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::FileSecurityDialog>(&[
                ("inheritance", |d, _| {
                    d.inheritance();
                    None
                }),
                ("owner", |d, _| {
                    d.choose_owner();
                    None
                }),
                ("audit_inheritance", |d, _| {
                    d.audit_inheritance();
                    None
                }),
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("add_everyone", |d, _| {
                    d.add_well_known("S-1-1-0");
                    None
                }),
                ("add_authenticated", |d, _| {
                    d.add_well_known("S-1-5-11");
                    None
                }),
                ("add_users", |d, _| {
                    d.add_well_known("S-1-5-32-545");
                    None
                }),
                ("add_administrators", |d, _| {
                    d.add_well_known("S-1-5-32-544");
                    None
                }),
                ("add_creator", |d, _| {
                    d.add_well_known("S-1-3-0");
                    None
                }),
                ("changed", |d, _| {
                    d.changed();
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("next", |d, _| {
                    d.proceed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for FileSecurityDialog {}
    impl WidgetImpl for FileSecurityDialog {}

    impl AdwDialogImpl for FileSecurityDialog {
        fn closed(&self) {
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// The « Security » tab of a file or folder of a share (`AnnuaireDialogueSecuriteNtfs`).
    pub struct FileSecurityDialog(ObjectSubclass<imp::FileSecurityDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl FileSecurityDialog {
    pub fn new(
        source: Arc<dyn Source>,
        connection: Option<Arc<annuaire_core::connection::Connection>>,
        files: ShareFiles,
        path: &str,
        folder: bool,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        *imp.connection.borrow_mut() = connection;
        imp.title.set_subtitle(&files.unc(path));
        imp.read_only.set(source.profile().read_only);
        *imp.path.borrow_mut() = path.to_owned();
        imp.folder.set(folder);
        let _ = imp.source.set(source);
        let _ = imp.files.set(files);
        imp.children_group.set_visible(folder);
        imp.creator_button.set_visible(folder);
        let read_only = imp.read_only.get();
        imp.add_group.set_visible(!read_only);
        imp.continue_button.set_visible(!read_only);
        imp.inheritance_button.set_visible(!read_only);
        imp.owner_button.set_visible(!read_only);
        imp.audit_inheritance_button.set_visible(!read_only);
        imp.children_group.set_sensitive(!read_only);
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(dialog) = weak.upgrade() {
                dialog.chosen(row);
            }
        });
        imp.state.set_visible_child_name("chargement");
        dialog.load();
        dialog
    }

    fn source(&self) -> Arc<dyn Source> {
        self.imp().source.get().expect("set by new").clone()
    }

    fn files(&self) -> &ShareFiles {
        self.imp().files.get().expect("set by new")
    }

    fn path(&self) -> String {
        self.imp().path.borrow().clone()
    }

    fn unc(&self) -> String {
        self.files().unc(&self.path())
    }

    /// The element and its ancestors in one batch, then the names of the SIDs.
    fn load(&self) {
        let path = self.path();
        let mut paths = vec![path.clone()];
        paths.extend(ancestors(&path));
        let files = self.files().clone();
        let server = files.server.clone();
        let protection =
            annuaire_core::sysvol::Protection::of_profile(self.source().profile().smb2_signing);
        let connection = self.imp().connection.borrow().clone();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            // With the SACL first (J8.7); an account without SeSecurityPrivilege is refused it,
            // and reads the rest again without it.
            let read = files
                .run(move |s| {
                    let with = s.descriptors(&paths, INFO_OGD | INFO_SACL)?;
                    match with.first() {
                        Some(Err(status))
                            if *status == PRIVILEGE_NOT_HELD || *status == ACCESS_DENIED =>
                        {
                            Ok((s.descriptors(&paths, INFO_OGD)?, Some(*status)))
                        }
                        _ => Ok((with, None)),
                    }
                })
                .await;
            let Some(dialog) = weak.upgrade() else { return };
            let (reads, audit_refused) = match read {
                Ok(r) => r,
                Err(error) => return dialog.failed(&file_problem(&error, &server)),
            };
            let mut reads = reads.into_iter();
            let bytes = match reads.next() {
                Some(Ok(bytes)) => bytes,
                Some(Err(status)) => {
                    let error = sysvol::SysvolError::status(status, &dialog.path());
                    return dialog.failed(&file_problem(&error, &server));
                }
                None => return,
            };
            let Ok(mut descriptor) = SecurityDescriptor::decode(&bytes) else {
                return dialog.failed(&errors::Problem {
                    message: tr("Unreadable permissions"),
                    detail: String::new(),
                    ticket: false,
                    kerberos: false,
                });
            };
            // Read with its SACL: said so, even without auditing entries (the « before » of
            // an undo that puts back an empty SACL).
            let bytes = if audit_refused.is_none() {
                ntfs::mark_sacl_read(&mut descriptor);
                descriptor.encode().unwrap_or(bytes)
            } else {
                bytes
            };
            let ancestors: Vec<Option<SecurityDescriptor>> = reads
                .map(|r| r.ok().and_then(|b| SecurityDescriptor::decode(&b).ok()))
                .collect();
            let sids: HashSet<Sid> = sids_of(&descriptor)
                .into_iter()
                .chain(ancestors.iter().flatten().flat_map(sids_of))
                .collect();
            let named =
                gio::spawn_blocking(move || name_all(connection, &server, sids, protection))
                    .await
                    .unwrap_or_default();
            dialog.loaded(Reading {
                bytes,
                descriptor,
                ancestors,
                names: named,
                audit_refused,
            });
        });
    }

    fn failed(&self, problem: &errors::Problem) {
        let imp = self.imp();
        imp.error.set_title(&tr("Permissions cannot be read"));
        imp.error
            .set_description(Some(&glib::markup_escape_text(&format!(
                "{}\n\n{}",
                problem.message, problem.detail
            ))));
        imp.state.set_visible_child_name("erreur");
    }

    fn loaded(&self, reading: Reading) {
        let imp = self.imp();
        *imp.explicit.borrow_mut() = ntfs::explicit_aces(&reading.descriptor);
        *imp.inherited.borrow_mut() = ntfs::inherited_of(&reading.descriptor);
        imp.protected.set(ntfs::is_protected(&reading.descriptor));
        let audit = reading.audit_refused.is_none() && ntfs::has_sacl(&reading.descriptor);
        imp.audit.set(audit);
        *imp.audit_explicit.borrow_mut() = ntfs::explicit_sacl(&reading.descriptor);
        *imp.audit_inherited.borrow_mut() = ntfs::inherited_sacl(&reading.descriptor);
        imp.audit_protected
            .set(ntfs::is_sacl_protected(&reading.descriptor));
        if !audit {
            imp.audit_unavailable
                .set_label(&audit_refusal(reading.audit_refused));
        }
        imp.audit_unavailable.set_visible(!audit);
        imp.audit_inheritance_row.set_visible(audit);
        imp.audit_list.set_visible(audit);
        imp.kind_row.set_visible(audit);
        imp.audit_replace_switch
            .set_visible(audit && imp.folder.get());
        *imp.ancestors.borrow_mut() = reading.ancestors;
        *imp.names.borrow_mut() = reading.names;
        *imp.before.borrow_mut() = Some((reading.bytes, reading.descriptor));
        imp.state.set_visible_child_name("contenu");
        self.show();
    }

    /// The owner the element will have: the one chosen, or the one read.
    fn owner(&self) -> Option<Sid> {
        let imp = self.imp();
        imp.owner
            .get()
            .or_else(|| imp.before.borrow().as_ref().and_then(|(_, d)| d.owner))
    }

    fn show_owner(&self) {
        let imp = self.imp();
        let names = imp.names.borrow().clone();
        let text = self.owner().map_or_else(
            || tr("(unknown)"),
            |o| format!("{} ({o})", sv::sid_name(&o, Some(&names))),
        );
        imp.owner_row.set_subtitle(&glib::markup_escape_text(&text));
    }

    /// « Change » next to the owner: myself, the Administrators group, or an account or group
    /// of the directory.
    fn choose_owner(&self) {
        let weak = self.downgrade();
        OwnerDialog::new(
            self.source(),
            self.imp().connection.borrow().clone(),
            Box::new(move |sid, name| {
                if let Some(dialog) = weak.upgrade() {
                    dialog.set_owner(sid, name);
                }
            }),
        )
        .present(Some(self));
    }

    fn set_owner(&self, sid: Sid, name: Option<String>) {
        let imp = self.imp();
        if let Some(name) = name {
            imp.names.borrow_mut().insert(
                sid,
                SidName {
                    sid,
                    name,
                    dn: String::new(),
                    classes: Vec::new(),
                },
            );
        }
        let read = imp.before.borrow().as_ref().and_then(|(_, d)| d.owner);
        imp.owner.set((read != Some(sid)).then_some(sid));
        self.show_owner();
        self.changed();
    }

    /// Where an inherited entry comes from: the UNC of the nearest ancestor read that holds
    /// it explicitly.
    fn source_of(&self, ace: &Ace) -> Option<String> {
        let imp = self.imp();
        let paths = ancestors(&self.path());
        // Only the ancestors read in a row from the parent count.
        let read: Vec<SecurityDescriptor> = imp
            .ancestors
            .borrow()
            .iter()
            .map_while(Clone::clone)
            .collect();
        let index = ntfs::inheritance_source(ace, &read)?;
        paths.get(index).map(|p| self.files().unc(p))
    }

    /// Where an inherited auditing entry comes from.
    fn audit_source_of(&self, ace: &Ace) -> Option<String> {
        let imp = self.imp();
        let paths = ancestors(&self.path());
        let read: Vec<SecurityDescriptor> = imp
            .ancestors
            .borrow()
            .iter()
            .map_while(Clone::clone)
            .collect();
        let index = ntfs::audit_source(ace, &read)?;
        paths.get(index).map(|p| self.files().unc(p))
    }

    /// The auditing entries (J8.7): explicit ones with « Edit » and « Remove », then the
    /// inherited ones.
    fn show_audit(&self) {
        let imp = self.imp();
        empty(&imp.audit_list);
        if !imp.audit.get() {
            return;
        }
        let folder = imp.folder.get();
        let names = imp.names.borrow().clone();
        let explicit = ntfs::canonical(&imp.audit_explicit.borrow());
        *imp.audit_explicit.borrow_mut() = explicit.clone();
        let inherited = imp.audit_inherited.borrow().clone();
        let read_only = imp.read_only.get();
        for (index, ace) in explicit.iter().enumerate() {
            let row = self.audit_row(ace, folder, &names, None);
            if !read_only {
                type Handler = fn(&FileSecurityDialog, usize);
                let actions: [(&str, String, Handler); 2] = [
                    ("document-edit-symbolic", tr("Edit"), Self::edit_audit),
                    ("list-remove-symbolic", tr("Remove"), Self::remove_audit),
                ];
                let who = ace
                    .sid()
                    .map_or_else(|| tr("(unknown)"), |s| sv::sid_name(&s, Some(&names)));
                for (icon, text, handler) in actions {
                    let button = gtk::Button::builder()
                        .icon_name(icon)
                        .valign(gtk::Align::Center)
                        .tooltip_text(text.as_str())
                        .build();
                    button.add_css_class("flat");
                    button.update_property(&[gtk::accessible::Property::Label(&fill(
                        &tr("{action}: auditing of {principal}"),
                        &[("action", &text), ("principal", &who)],
                    ))]);
                    let weak = self.downgrade();
                    button.connect_clicked(move |_| {
                        if let Some(dialog) = weak.upgrade() {
                            handler(&dialog, index);
                        }
                    });
                    row.add_suffix(&button);
                }
            }
            imp.audit_list.append(&row);
        }
        for ace in &inherited {
            let source = self.audit_source_of(ace);
            imp.audit_list
                .append(&self.audit_row(ace, folder, &names, Some(source)));
        }
        let none = explicit.is_empty() && inherited.is_empty();
        imp.audit_list.set_visible(!none);
        imp.audit_none.set_visible(none);
        let protected = imp.audit_protected.get();
        imp.audit_inheritance_row
            .set_subtitle(&shv::inheritance_text(protected, self.path().is_empty()));
        imp.audit_inheritance_button.set_label(&if protected {
            tr("Enable Inheritance")
        } else {
            tr("Disable Inheritance…")
        });
    }

    fn audit_row(
        &self,
        ace: &Ace,
        folder: bool,
        names: &Names,
        source: Option<Option<String>>,
    ) -> adw::ActionRow {
        let who = ace
            .sid()
            .map_or_else(|| tr("(unknown)"), |s| sv::sid_name(&s, Some(names)));
        let from = source.flatten();
        let subtitle = shv::audit_entry_subtitle(ace, folder, from.as_deref());
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&who).as_str())
            .subtitle(glib::markup_escape_text(&subtitle).as_str())
            .subtitle_lines(0)
            .build();
        let icon = gtk::Image::from_icon_name("system-search-symbolic");
        icon.update_property(&[gtk::accessible::Property::Label(&shv::audit_type_text(
            ace.flags,
        ))]);
        row.add_prefix(&icon);
        row
    }

    fn show(&self) {
        let imp = self.imp();
        self.show_audit();
        empty(&imp.entries_list);
        let folder = imp.folder.get();
        let names = imp.names.borrow().clone();
        self.show_owner();
        let explicit = ntfs::canonical(&imp.explicit.borrow());
        *imp.explicit.borrow_mut() = explicit.clone();
        let inherited = imp.inherited.borrow().clone();
        let read_only = imp.read_only.get();
        for (index, ace) in explicit.iter().enumerate() {
            let row = self.entry_row(ace, folder, &names, None);
            if !read_only {
                type Handler = fn(&FileSecurityDialog, usize);
                let actions: [(&str, String, Handler); 2] = [
                    ("document-edit-symbolic", tr("Edit"), Self::edit),
                    ("list-remove-symbolic", tr("Remove"), Self::remove),
                ];
                let who = ace
                    .sid()
                    .map_or_else(|| tr("(unknown)"), |s| sv::sid_name(&s, Some(&names)));
                for (icon, text, handler) in actions {
                    let button = gtk::Button::builder()
                        .icon_name(icon)
                        .valign(gtk::Align::Center)
                        .tooltip_text(text.as_str())
                        .build();
                    button.add_css_class("flat");
                    button.update_property(&[gtk::accessible::Property::Label(&format!(
                        "{text} : {who}"
                    ))]);
                    let weak = self.downgrade();
                    button.connect_clicked(move |_| {
                        if let Some(dialog) = weak.upgrade() {
                            handler(&dialog, index);
                        }
                    });
                    row.add_suffix(&button);
                }
            }
            imp.entries_list.append(&row);
        }
        for ace in &inherited {
            let source = self.source_of(ace);
            let row = self.entry_row(ace, folder, &names, Some(source));
            imp.entries_list.append(&row);
        }
        imp.entries_list
            .set_visible(!explicit.is_empty() || !inherited.is_empty());
        let protected = imp.protected.get();
        imp.inheritance_row
            .set_subtitle(&shv::inheritance_text(protected, self.path().is_empty()));
        imp.inheritance_button.set_label(&if protected {
            tr("Enable Inheritance")
        } else {
            tr("Disable Inheritance…")
        });
        self.changed();
    }

    fn entry_row(
        &self,
        ace: &Ace,
        folder: bool,
        names: &Names,
        source: Option<Option<String>>,
    ) -> adw::ActionRow {
        let who = ace
            .sid()
            .map_or_else(|| tr("(unknown)"), |s| sv::sid_name(&s, Some(names)));
        let from = source.flatten();
        let subtitle = shv::file_entry_subtitle(ace, folder, from.as_deref());
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&who).as_str())
            .subtitle(glib::markup_escape_text(&subtitle).as_str())
            .subtitle_lines(0)
            .build();
        let icon = gtk::Image::from_icon_name(if ace.is_deny() {
            "action-unavailable-symbolic"
        } else {
            "object-select-symbolic"
        });
        icon.update_property(&[gtk::accessible::Property::Label(&if ace.is_deny() {
            tr("Deny")
        } else {
            tr("Allow")
        })]);
        row.add_prefix(&icon);
        row
    }

    /// The descriptor the choices give, or why there is nothing to write.
    fn compose(&self) -> Option<SecurityDescriptor> {
        let imp = self.imp();
        let before = imp.before.borrow();
        let (_, origin) = before.as_ref()?;
        let mut composed = ntfs::composed(
            origin,
            &imp.explicit.borrow(),
            &imp.inherited.borrow(),
            imp.protected.get(),
        );
        if let Some(owner) = imp.owner.get() {
            composed.owner = Some(owner);
        }
        // The SACL as read, unless its entries or their inheritance changed (J8.7): then as
        // `SetSecurityInfo` writes it.
        composed.sacl = origin.sacl.clone();
        composed.control |= origin.control & SACL_BITS;
        if imp.audit.get() {
            let audit = ntfs::with_sacl(
                origin,
                &imp.audit_explicit.borrow(),
                &imp.audit_inherited.borrow(),
                imp.audit_protected.get(),
            );
            if !ntfs::same_audit(&audit, origin) {
                composed.sacl = audit.sacl;
                composed.control = (composed.control & !SACL_BITS) | (audit.control & SACL_BITS);
            }
        }
        Some(composed)
    }

    fn changed(&self) {
        let imp = self.imp();
        let after = self.compose();
        let unchanged = match (&after, imp.before.borrow().as_ref()) {
            (Some(a), Some((_, b))) => {
                ntfs::same_permissions(a, b) && a.owner == b.owner && ntfs::same_audit(a, b)
            }
            _ => true,
        };
        let replace = imp.folder.get()
            && (imp.replace_switch.is_active()
                || imp.owner_replace_switch.is_active()
                || (imp.audit.get() && imp.audit_replace_switch.is_active()));
        let error = if after.is_none() {
            tr("These permissions cannot be encoded.")
        } else if unchanged && !replace {
            tr("Nothing has changed.")
        } else {
            String::new()
        };
        imp.nobody_label
            .set_visible(after.as_ref().is_some_and(|a| ntfs::dacl_of(a).is_empty()));
        imp.problems.set_label(&error);
        imp.problems_group
            .set_visible(!error.is_empty() && error != tr("Nothing has changed."));
        imp.continue_button.set_sensitive(error.is_empty());
        *imp.after.borrow_mut() = after;
    }

    // --- Edits -------------------------------------------------------------------------------

    fn name_of(&self, sid: &Sid) -> String {
        sv::sid_name(sid, Some(&self.imp().names.borrow()))
    }

    fn edit(&self, index: usize) {
        let Some(ace) = self.imp().explicit.borrow().get(index).cloned() else {
            return;
        };
        let Some(sid) = ace.sid() else { return };
        let weak = self.downgrade();
        FileAceDialog::new(
            &self.name_of(&sid),
            ace,
            self.imp().folder.get(),
            false,
            Box::new(move |new| {
                if let Some(dialog) = weak.upgrade() {
                    if let Some(slot) = dialog.imp().explicit.borrow_mut().get_mut(index) {
                        *slot = new;
                    }
                    dialog.show();
                }
            }),
        )
        .present(Some(self));
    }

    fn edit_audit(&self, index: usize) {
        let Some(ace) = self.imp().audit_explicit.borrow().get(index).cloned() else {
            return;
        };
        let Some(sid) = ace.sid() else { return };
        let weak = self.downgrade();
        FileAceDialog::new(
            &self.name_of(&sid),
            ace,
            self.imp().folder.get(),
            true,
            Box::new(move |new| {
                if let Some(dialog) = weak.upgrade() {
                    if let Some(slot) = dialog.imp().audit_explicit.borrow_mut().get_mut(index) {
                        *slot = new;
                    }
                    dialog.show();
                }
            }),
        )
        .present(Some(self));
    }

    fn remove_audit(&self, index: usize) {
        let imp = self.imp();
        if index < imp.audit_explicit.borrow().len() {
            imp.audit_explicit.borrow_mut().remove(index);
        }
        self.show();
    }

    /// An auditing entry for a principal added (J8.7): success, with the rights and the
    /// scope Windows offers for a permission.
    fn add_audit(&self, sid: Sid) {
        let folder = self.imp().folder.get();
        let Some(mut ace) = shv::new_entry(&sid, folder) else {
            return;
        };
        ace.ace_type = annuaire_codecs::sd::SYSTEM_AUDIT;
        ace.flags |= annuaire_codecs::sd::SUCCESSFUL_ACCESS_ACE;
        let weak = self.downgrade();
        FileAceDialog::new(
            &self.name_of(&sid),
            ace,
            folder,
            true,
            Box::new(move |new| {
                if let Some(dialog) = weak.upgrade() {
                    dialog.imp().audit_explicit.borrow_mut().push(new);
                    dialog.show();
                }
            }),
        )
        .present(Some(self));
    }

    /// Disables the inheritance of the auditing entries (convert or remove), or turns it on.
    fn audit_inheritance(&self) {
        let imp = self.imp();
        if imp.audit_protected.get() {
            let Some(origin) = self.compose() else { return };
            let parent = imp.ancestors.borrow().first().cloned().flatten();
            let on = ntfs::sacl_with_inheritance(
                &origin,
                parent.as_ref().filter(|_| !self.path().is_empty()),
                imp.folder.get(),
            );
            *imp.audit_inherited.borrow_mut() = ntfs::inherited_sacl(&on);
            imp.audit_protected.set(false);
            self.show();
            return;
        }
        let alert = adw::AlertDialog::new(
            Some(&tr("Disable Inheritance")),
            Some(&tr(
                "What should become of the auditing entries inherited from the parent folder?",
            )),
        );
        alert.add_response("annuler", &tr("Cancel"));
        alert.add_response("supprimer", &tr("Remove All Inherited Entries"));
        alert.add_response("convertir", &tr("Convert into Explicit Entries"));
        alert.set_response_appearance("supprimer", adw::ResponseAppearance::Destructive);
        alert.set_default_response(Some("convertir"));
        alert.set_close_response("annuler");
        let weak = self.downgrade();
        alert.connect_response(None, move |_, response| {
            if let Some(dialog) = weak.upgrade() {
                match response {
                    "convertir" => dialog.disable_audit_inheritance(true),
                    "supprimer" => dialog.disable_audit_inheritance(false),
                    _ => {}
                }
            }
        });
        alert.present(Some(self));
    }

    fn disable_audit_inheritance(&self, convert: bool) {
        let imp = self.imp();
        let Some(origin) = self.compose() else { return };
        let off = ntfs::sacl_without_inheritance(&origin, convert);
        *imp.audit_explicit.borrow_mut() = ntfs::explicit_sacl(&off);
        imp.audit_inherited.borrow_mut().clear();
        imp.audit_protected.set(true);
        self.show();
    }

    fn remove(&self, index: usize) {
        let imp = self.imp();
        if index < imp.explicit.borrow().len() {
            imp.explicit.borrow_mut().remove(index);
        }
        self.show();
    }

    /// A principal added: its entry, as Windows offers it, in the entry dialog; an auditing
    /// entry if « Kind of entry » says so.
    fn add(&self, sid: Sid) {
        if self.imp().audit.get() && self.imp().kind_row.selected() == 1 {
            self.add_audit(sid);
            return;
        }
        let folder = self.imp().folder.get();
        let Some(ace) = shv::new_entry(&sid, folder) else {
            return;
        };
        let weak = self.downgrade();
        FileAceDialog::new(
            &self.name_of(&sid),
            ace,
            folder,
            false,
            Box::new(move |new| {
                if let Some(dialog) = weak.upgrade() {
                    dialog.imp().explicit.borrow_mut().push(new);
                    dialog.show();
                }
            }),
        )
        .present(Some(self));
    }

    fn add_well_known(&self, text: &str) {
        if let Ok(sid) = text.parse::<Sid>() {
            self.add(sid);
        }
    }

    /// Disables inheritance (Windows' two choices), or turns it on again.
    fn inheritance(&self) {
        let imp = self.imp();
        if imp.protected.get() {
            self.enable_inheritance();
            return;
        }
        let alert = adw::AlertDialog::new(
            Some(&tr("Disable Inheritance")),
            Some(&tr(
                "What should become of the entries inherited from the parent folder?",
            )),
        );
        alert.add_response("annuler", &tr("Cancel"));
        alert.add_response("supprimer", &tr("Remove All Inherited Entries"));
        alert.add_response("convertir", &tr("Convert into Explicit Entries"));
        alert.set_response_appearance("supprimer", adw::ResponseAppearance::Destructive);
        alert.set_default_response(Some("convertir"));
        alert.set_close_response("annuler");
        let weak = self.downgrade();
        alert.connect_response(None, move |_, response| {
            if let Some(dialog) = weak.upgrade() {
                match response {
                    "convertir" => dialog.disable_inheritance(true),
                    "supprimer" => dialog.disable_inheritance(false),
                    _ => {}
                }
            }
        });
        alert.present(Some(self));
    }

    fn disable_inheritance(&self, convert: bool) {
        let imp = self.imp();
        let Some(origin) = self.compose() else { return };
        let off = ntfs::without_inheritance(&origin, convert);
        *imp.explicit.borrow_mut() = ntfs::explicit_aces(&off);
        imp.inherited.borrow_mut().clear();
        imp.protected.set(true);
        self.show();
    }

    fn enable_inheritance(&self) {
        let imp = self.imp();
        let Some(origin) = self.compose() else { return };
        let parent = imp.ancestors.borrow().first().cloned().flatten();
        let on = ntfs::with_inheritance(
            &origin,
            parent.as_ref().filter(|_| !self.path().is_empty()),
            imp.folder.get(),
        );
        *imp.inherited.borrow_mut() = ntfs::inherited_of(&on);
        imp.protected.set(false);
        self.show();
    }

    // --- Search of a principal ---------------------------------------------------------------

    fn stop(&self) {
        if let Some(feed) = self.imp().search.take() {
            feed.cancel();
        }
    }

    fn search(&self) {
        self.stop();
        let imp = self.imp();
        empty(&imp.candidates_list);
        imp.received.borrow_mut().clear();
        imp.candidates_list.set_visible(false);
        let Some(filter) = sv::delegates_filter(&imp.principal_entry.text()) else {
            imp.candidates_count.set_label("");
            return;
        };
        imp.candidates_count.set_label(&tr("Searching…"));
        let source = self.source();
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = deliver_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                for item in &items {
                    let view = sheet::element_from_item(item);
                    if imp.received.borrow().len() < MAX_RESULTS {
                        imp.candidates_list
                            .append(&candidate_row(&view, &tr("Add")));
                    }
                    imp.received.borrow_mut().push((view, object_sid(item)));
                }
                imp.candidates_list
                    .set_visible(!imp.received.borrow().is_empty());
                let n = imp.received.borrow().len();
                imp.candidates_count.set_label(&count_text(n, false));
            },
            move |error| {
                let Some(dialog) = finish_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                imp.search.take();
                match error {
                    Some(error) => imp
                        .candidates_count
                        .set_label(&errors::search_problem(&error, &domain).message),
                    None => {
                        let n = imp.received.borrow().len();
                        imp.candidates_count.set_label(&count_text(n, true));
                    }
                }
            },
        );
        *imp.search.borrow_mut() = Some(feed);
    }

    fn chosen(&self, row: &gtk::ListBoxRow) {
        let imp = self.imp();
        let dn = row.widget_name().to_string();
        let found = imp
            .received
            .borrow()
            .iter()
            .find(|(v, _)| v.dn == dn)
            .cloned();
        let Some((view, sid)) = found else { return };
        imp.principal_entry.set_text("");
        let (title, target) = (view.title.clone(), view.dn.clone());
        let name = move |dialog: &Self, sid: Sid| {
            dialog.imp().names.borrow_mut().insert(
                sid,
                SidName {
                    sid,
                    name: title.clone(),
                    dn: target.clone(),
                    classes: Vec::new(),
                },
            );
            dialog.add(sid);
        };
        if let Some(sid) = sid {
            name(self, sid);
            return;
        }
        // The local copy may not carry the SID: it is read on the DC.
        let (source, weak) = (self.source(), self.downgrade());
        let target = view.dn.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || source.record(&target, &["objectSid"])).await;
            let Some(dialog) = weak.upgrade() else { return };
            match read {
                Ok(Ok(Some(record))) => {
                    if let Some(sid) = record
                        .values("objectSid")
                        .first()
                        .and_then(|v| Sid::decode(v).ok())
                    {
                        name(&dialog, sid);
                    }
                }
                Ok(Err(failure)) => {
                    let domain = dialog.source().profile().domain.clone();
                    let problem = errors::failure_problem(&failure, &domain);
                    writes::show_error(
                        &dialog,
                        &tr("Unreadable SID"),
                        &problem.message,
                        &problem.detail,
                    );
                }
                _ => {}
            }
        });
    }

    // --- Writing -----------------------------------------------------------------------------

    /// Does the write call for a propagation (what the children inherit changes, « Replace »,
    /// or the owner replaced below)?
    fn propagates(&self) -> bool {
        let imp = self.imp();
        imp.folder.get()
            && (self.propagates_dacl()
                || imp.owner_replace_switch.is_active()
                || self.propagates_audit())
    }

    /// Does the propagation recompute the auditing entries of the descendants (J8.7)?
    fn propagates_audit(&self) -> bool {
        let imp = self.imp();
        if !imp.folder.get() || !imp.audit.get() {
            return false;
        }
        if imp.audit_replace_switch.is_active() {
            return true;
        }
        match (imp.after.borrow().as_ref(), imp.before.borrow().as_ref()) {
            (Some(after), Some((_, before))) => ntfs::changes_children_audit(before, after),
            _ => false,
        }
    }

    /// Does the propagation recompute the DACL of the descendants?
    fn propagates_dacl(&self) -> bool {
        let imp = self.imp();
        if !imp.folder.get() {
            return false;
        }
        if imp.replace_switch.is_active() {
            return true;
        }
        match (imp.after.borrow().as_ref(), imp.before.borrow().as_ref()) {
            (Some(after), Some((_, before))) => ntfs::changes_children(before, after),
            _ => false,
        }
    }

    fn proceed(&self) {
        self.changed();
        if !self.imp().continue_button.is_sensitive() {
            return;
        }
        if !self.propagates() {
            self.propose(None);
            return;
        }
        // The descendants counted before the confirmation.
        let imp = self.imp();
        imp.continue_button.set_sensitive(false);
        imp.continue_button.set_label(&tr("Counting…"));
        let (files, weak, path) = (self.files().clone(), self.downgrade(), self.path());
        glib::spawn_future_local(async move {
            let counted = files.run(move |s| propagation::count(s, &path)).await;
            let Some(dialog) = weak.upgrade() else { return };
            let imp = dialog.imp();
            imp.continue_button.set_label(&tr("Continue…"));
            imp.continue_button.set_sensitive(true);
            match counted {
                Ok((folders, files)) => dialog.confirm(folders, files),
                Err(error) => {
                    let problem = file_problem(&error, &dialog.files().server);
                    writes::show_error(
                        &dialog,
                        &tr("The subfolders cannot be counted"),
                        &problem.message,
                        &problem.detail,
                    );
                }
            }
        });
    }

    /// The confirmation of a propagation, apart from the preview: how many elements, where
    /// their descriptors are saved, that it can be stopped and undone.
    fn confirm(&self, folders: usize, files: usize) {
        let total = folders + files;
        let replace = self.imp().replace_switch.is_active();
        let dacl = self.propagates_dacl();
        let heading = fill(
            &tr_n(
                "Propagate to {n} element?",
                "Propagate to {n} elements?",
                total as u64,
            ),
            &[("n", &total.to_string())],
        );
        let what = if replace {
            tr(
                "The permissions of the {dossiers} folders and {fichiers} files under {chemin} will be replaced by those they inherit: their explicit entries removed, their inheritance turned on again.",
            )
        } else {
            tr(
                "The inherited permissions of the {dossiers} folders and {fichiers} files under {chemin} will be computed again; their explicit entries stay, and nothing changes under a folder whose inheritance is disabled.",
            )
        };
        let fields = [
            ("dossiers", folders.to_string()),
            ("fichiers", files.to_string()),
            ("chemin", self.unc()),
        ];
        let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut first = Vec::new();
        if dacl {
            first.push(fill(&what, &fields));
        }
        if self.propagates_audit() {
            first.push(fill(
                &if self.imp().audit_replace_switch.is_active() {
                    tr(
                        "The auditing entries of the {dossiers} folders and {fichiers} files under {chemin} will be replaced by those they inherit.",
                    )
                } else {
                    tr(
                        "The inherited auditing entries of the {dossiers} folders and {fichiers} files under {chemin} will be computed again.",
                    )
                },
                &fields,
            ));
        }
        if self.imp().owner_replace_switch.is_active() {
            let names = self.imp().names.borrow().clone();
            let owner = self
                .owner()
                .map_or_else(|| tr("(unknown)"), |o| sv::sid_name(&o, Some(&names)));
            let mut with_owner = fields.clone();
            with_owner.push(("proprietaire", &owner));
            first.push(fill(
                &tr(
                    "The owner of the {dossiers} folders and {fichiers} files under {chemin} will be {proprietaire}.",
                ),
                &with_owner,
            ));
        }
        let text = format!(
            "{}\n\n{}",
            first.join(" "),
            fill(
                &tr(
                    "Before an element is written, its descriptor is saved in {dossier}. The writing can be stopped: what is written stays written and saved. Ctrl+Z writes the saved descriptors back.",
                ),
                &[("dossier", &propagation::backup_dir().display().to_string(),)],
            )
        );
        let alert = adw::AlertDialog::new(Some(&heading), Some(&text));
        alert.add_response("annuler", &tr("Cancel"));
        alert.add_response("propager", &tr("Continue to the Preview"));
        alert.set_response_appearance("propager", adw::ResponseAppearance::Suggested);
        alert.set_default_response(Some("propager"));
        alert.set_close_response("annuler");
        let weak = self.downgrade();
        alert.connect_response(None, move |_, response| {
            if let Some(dialog) = weak.upgrade() {
                dialog.imp().confirmation.take();
                if response == "propager" {
                    dialog.propose(Some(total));
                }
            }
        });
        *self.imp().confirmation.borrow_mut() = Some((alert.clone(), total));
        alert.present(Some(self));
    }

    /// The changeset to the common preview: the descriptor if it changes, then the
    /// propagation of `count` elements if any.
    fn propose(&self, count: Option<usize>) {
        let imp = self.imp();
        let (Some(after), Some((before, before_sd))) =
            (imp.after.borrow().clone(), imp.before.borrow().clone())
        else {
            return;
        };
        let Ok(after_bytes) = after.encode() else {
            return;
        };
        let files = self.files().clone();
        let path = self.path();
        let unc = self.unc();
        let mut operations = Vec::new();
        let mut remarks = Vec::new();
        if !ntfs::same_permissions(&after, &before_sd)
            || after.owner != before_sd.owner
            || !ntfs::same_audit(&after, &before_sd)
        {
            operations.push(Operation::set_file_descriptor(
                &files.server,
                &files.share,
                &path,
                before,
                after_bytes,
            ));
            remarks.push(fill(
                &tr("NTFS permissions of {chemin}; the permissions of the share do not change."),
                &[("chemin", &unc)],
            ));
        }
        if after.owner != before_sd.owner {
            let names = imp.names.borrow().clone();
            let owner = after
                .owner
                .map_or_else(|| tr("(unknown)"), |o| sv::sid_name(&o, Some(&names)));
            remarks.push(fill(
                &tr("The owner of {chemin} becomes {proprietaire}."),
                &[("chemin", &unc), ("proprietaire", &owner)],
            ));
        }
        if let Some(n) = count {
            let replace = imp.replace_switch.is_active();
            let parts = propagation::Parts {
                dacl: self.propagates_dacl(),
                sacl: self
                    .propagates_audit()
                    .then(|| imp.audit_replace_switch.is_active()),
                owner: if imp.owner_replace_switch.is_active() {
                    after.owner
                } else {
                    None
                },
            };
            operations.push(Operation::propagate_parts(
                &files.server,
                &files.share,
                &path,
                replace,
                parts,
                &propagation::new_id(),
                n,
            ));
            remarks.push(tr(
                "The propagation can be stopped from this window while it writes; what is written stays saved.",
            ));
        }
        if ntfs::dacl_of(&after).is_empty() {
            remarks.push(tr(
                "Nobody but the owner will be able to open this element.",
            ));
        }
        let weak = self.downgrade();
        writes::propose(
            self,
            Changeset {
                operations,
                remarks,
            },
            Options {
                finished: Some(Box::new(move |report| {
                    if let Some(dialog) = weak.upgrade() {
                        dialog.written(report);
                    }
                })),
                ..Options::default()
            },
        );
    }

    fn written(&self, report: Option<&Report>) {
        if report.is_some() {
            self.close();
        }
    }

    // --- Trials ------------------------------------------------------------------------------

    /// Read and shown (trials).
    pub fn trial_ready(&self) -> bool {
        self.imp().state.visible_child_name().as_deref() != Some("chargement")
    }

    /// Owner, inheritance, then each entry: principal and what it says (trials).
    pub fn trial_rows(&self) -> Vec<String> {
        let imp = self.imp();
        let mut out = vec![
            format!(
                "propriétaire | {}",
                imp.owner_row.subtitle().unwrap_or_default()
            ),
            format!(
                "héritage | {}",
                imp.inheritance_row.subtitle().unwrap_or_default()
            ),
        ];
        if imp.state.visible_child_name().as_deref() == Some("erreur") {
            out.push(format!(
                "erreur | {} | {}",
                imp.error.title(),
                imp.error.description().unwrap_or_default()
            ));
        }
        let mut i = 0;
        while let Some(row) = imp.entries_list.row_at_index(i) {
            if let Some(r) = row.downcast_ref::<adw::ActionRow>() {
                out.push(format!(
                    "{} | {}",
                    r.title(),
                    r.subtitle().unwrap_or_default()
                ));
            }
            i += 1;
        }
        if imp.audit.get() {
            out.push(format!(
                "audit, héritage | {}",
                imp.audit_inheritance_row.subtitle().unwrap_or_default()
            ));
            let mut i = 0;
            while let Some(row) = imp.audit_list.row_at_index(i) {
                if let Some(r) = row.downcast_ref::<adw::ActionRow>() {
                    out.push(format!(
                        "audit : {} | {}",
                        r.title(),
                        r.subtitle().unwrap_or_default()
                    ));
                }
                i += 1;
            }
        } else {
            out.push(format!("audit | {}", imp.audit_unavailable.label()));
        }
        out
    }

    /// Adds an auditing entry without the dialog: `sid`, `reussite`, `echec` or `tout`,
    /// `mask`, scope by its index in `SCOPES` (trials).
    pub fn trial_add_audit(&self, sid: &str, kind: &str, mask: u32, scope: usize) {
        use annuaire_codecs::sd::{FAILED_ACCESS_ACE, SUCCESSFUL_ACCESS_ACE, SYSTEM_AUDIT};
        let Ok(sid) = sid.parse::<Sid>() else { return };
        let scope = if self.imp().folder.get() {
            shv::SCOPES
                .get(scope)
                .copied()
                .unwrap_or(shv::Scope::FolderSubfoldersFiles)
        } else {
            shv::Scope::ThisFolder
        };
        if let Some(mut ace) = shv::entry_ace(false, mask, scope, false, &sid) {
            ace.ace_type = SYSTEM_AUDIT;
            ace.flags |= match kind {
                "echec" => FAILED_ACCESS_ACE,
                "tout" => SUCCESSFUL_ACCESS_ACE | FAILED_ACCESS_ACE,
                _ => SUCCESSFUL_ACCESS_ACE,
            };
            self.imp().audit_explicit.borrow_mut().push(ace);
        }
        self.show();
    }

    /// Removes the explicit auditing entries of `sid` (trials).
    pub fn trial_remove_audit(&self, sid: &str) {
        let Ok(sid) = sid.parse::<Sid>() else { return };
        self.imp()
            .audit_explicit
            .borrow_mut()
            .retain(|a| a.sid() != Some(sid));
        self.show();
    }

    /// `convertir`, `supprimer` or `activer`, for the auditing entries (trials).
    pub fn trial_audit_inheritance(&self, how: &str) {
        match how {
            "convertir" => self.disable_audit_inheritance(true),
            "supprimer" => self.disable_audit_inheritance(false),
            _ => {
                if self.imp().audit_protected.get() {
                    self.audit_inheritance();
                }
            }
        }
    }

    pub fn trial_audit_replace(&self, on: bool) {
        self.imp().audit_replace_switch.set_active(on);
    }

    /// Opens the dialog of an auditing entry for `sid` (trials, for the audit).
    pub fn trial_open_audit_entry(&self, sid: &str) {
        if let Ok(sid) = sid.parse::<Sid>() {
            self.add_audit(sid);
        }
    }

    /// Adds an explicit entry without the entry dialog: `sid`, allowed or denied, `mask`,
    /// scope by its index in `SCOPES` (trials).
    pub fn trial_add(&self, sid: &str, deny: bool, mask: u32, scope: usize) {
        let Ok(sid) = sid.parse::<Sid>() else { return };
        let scope = if self.imp().folder.get() {
            shv::SCOPES
                .get(scope)
                .copied()
                .unwrap_or(shv::Scope::FolderSubfoldersFiles)
        } else {
            shv::Scope::ThisFolder
        };
        if let Some(ace) = shv::entry_ace(deny, mask, scope, false, &sid) {
            self.imp().explicit.borrow_mut().push(ace);
        }
        self.show();
    }

    /// Removes the explicit entries of `sid` (trials).
    pub fn trial_remove(&self, sid: &str) {
        let Ok(sid) = sid.parse::<Sid>() else { return };
        self.imp()
            .explicit
            .borrow_mut()
            .retain(|a| a.sid() != Some(sid));
        self.show();
    }

    /// `convertir`, `supprimer` (inheritance disabled) or `activer` (trials).
    pub fn trial_inheritance(&self, how: &str) {
        match how {
            "convertir" => self.disable_inheritance(true),
            "supprimer" => self.disable_inheritance(false),
            _ => self.enable_inheritance(),
        }
    }

    pub fn trial_replace(&self, on: bool) {
        self.imp().replace_switch.set_active(on);
    }

    /// The owner chosen without the dialog (`moi`: the account, else a SID), and « Replace
    /// owner on subcontainers and objects » (trials).
    pub fn trial_owner(&self, sid: &str, below: bool) {
        self.imp().owner_replace_switch.set_active(below);
        if sid == "moi" {
            let (connection, weak) = (self.imp().connection.borrow().clone(), self.downgrade());
            glib::spawn_future_local(async move {
                let found = gio::spawn_blocking(move || {
                    connection.and_then(|c| annuaire_core::security::own_sid(&c).ok().flatten())
                })
                .await
                .ok()
                .flatten();
                if let (Some(dialog), Some(sid)) = (weak.upgrade(), found) {
                    dialog.set_owner(sid, None);
                }
            });
        } else if let Ok(sid) = sid.parse::<Sid>() {
            self.set_owner(sid, None);
        }
    }

    /// Opens the dialog of the owner (trials, for the audit).
    pub fn trial_open_owner(&self) {
        self.choose_owner();
    }

    /// « Continue » (trials).
    pub fn trial_proceed(&self) {
        self.proceed();
    }

    /// The count of the confirmation shown, if any (trials).
    pub fn trial_confirmation(&self) -> Option<usize> {
        self.imp().confirmation.borrow().as_ref().map(|(_, n)| *n)
    }

    /// Opens the entry dialog of a principal added (trials, for the audit).
    pub fn trial_open_entry(&self, sid: &str) {
        self.add_well_known(sid);
    }

    /// Answers the confirmation of a propagation (trials).
    pub fn trial_confirm(&self, propagate: bool) {
        let Some((alert, total)) = self.imp().confirmation.take() else {
            return;
        };
        alert.close();
        if propagate {
            self.propose(Some(total));
        }
    }
}

/// Names of SIDs: by the directory, then, for those it does not name, by the file server
/// (`lsarpc`); a name the server gives is `DOMAIN\name`.
pub fn name_all(
    connection: Option<Arc<annuaire_core::connection::Connection>>,
    server: &str,
    sids: HashSet<Sid>,
    protection: annuaire_core::sysvol::Protection,
) -> Names {
    let mut names: Names = connection
        .and_then(|c| annuaire_core::security::name_sids(&c, sids.clone()).ok())
        .unwrap_or_default();
    let missing: Vec<Sid> = sids
        .into_iter()
        .filter(|s| names.get(s).is_none_or(|n| n.name.is_empty()))
        .filter(|s| sv::sid_name(s, None) == s.to_string())
        .collect();
    if missing.is_empty() {
        return names;
    }
    let options = protection.options(std::time::Duration::from_secs(30));
    if let Ok(found) = annuaire_core::lsarpc::name_sids(server, &missing, &options) {
        for (sid, name) in found {
            names.insert(
                sid,
                SidName {
                    sid,
                    name,
                    dn: String::new(),
                    classes: Vec::new(),
                },
            );
        }
    }
    names
}

// --- One permission entry -----------------------------------------------------------------------

/// What follows the entry dialog: the entry chosen.
type Chosen = Box<dyn FnOnce(Ace)>;

mod entry_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-entree-ntfs.ui")]
    pub struct FileAceDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub type_row: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub scope_row: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub level_row: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub one_level_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub rights_group: TemplateChild<adw::PreferencesGroup>,
        pub rights: RefCell<Vec<(u32, adw::SwitchRow)>>,
        pub original: RefCell<Option<Ace>>,
        pub folder: Cell<bool>,
        /// An auditing entry (SACL, J8.7), not a permission.
        pub audit: Cell<bool>,
        pub mask: Cell<u32>,
        pub updating: Cell<bool>,
        pub chosen: RefCell<Option<Chosen>>,
    }

    impl std::fmt::Debug for FileAceDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FileAceDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for FileAceDialog {
        const NAME: &'static str = "AnnuaireDialogueEntreeNtfs";
        type Type = super::FileAceDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::FileAceDialog>(&[
                ("changed", |_, _| None),
                ("level_chosen", |d, _| {
                    d.level_chosen();
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("confirm", |d, _| {
                    d.confirm();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for FileAceDialog {}
    impl WidgetImpl for FileAceDialog {}
    impl AdwDialogImpl for FileAceDialog {}
}

glib::wrapper! {
    /// One NTFS permission entry (`AnnuaireDialogueEntreeNtfs`).
    pub struct FileAceDialog(ObjectSubclass<entry_imp::FileAceDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

/// The levels of the « Permissions » choice: the basic ones, then « Special permissions ».
fn levels() -> Vec<FileLevel> {
    let mut all = shv::FILE_LEVELS.to_vec();
    all.push(FileLevel::Special);
    all
}

impl FileAceDialog {
    pub fn new(name: &str, ace: Ace, folder: bool, audit: bool, chosen: Chosen) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.title.set_subtitle(&glib::markup_escape_text(name));
        imp.folder.set(folder);
        imp.audit.set(audit);
        imp.updating.set(true);
        if audit {
            // As the « Auditing Entry » of Windows: success, failure, or both.
            let title = tr("Auditing Entry");
            dialog.set_title(&title);
            imp.title.set_title(&title);
            let kinds = [tr("Success"), tr("Failure"), tr("All (auditing)")];
            let kinds: Vec<&str> = kinds.iter().map(String::as_str).collect();
            imp.type_row.set_model(Some(&gtk::StringList::new(&kinds)));
            let success = ace.flags & annuaire_codecs::sd::SUCCESSFUL_ACCESS_ACE != 0;
            let failure = ace.flags & annuaire_codecs::sd::FAILED_ACCESS_ACE != 0;
            imp.type_row.set_selected(match (success, failure) {
                (true, true) => 2,
                (false, true) => 1,
                _ => 0,
            });
        } else {
            imp.type_row.set_selected(u32::from(ace.is_deny()));
        }
        let scopes: Vec<String> = shv::SCOPES.iter().map(|s| shv::scope_text(*s)).collect();
        let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
        imp.scope_row
            .set_model(Some(&gtk::StringList::new(&scopes)));
        let scope = shv::scope_of(ace.flags);
        imp.scope_row
            .set_selected(shv::SCOPES.iter().position(|s| *s == scope).unwrap_or(1) as u32);
        imp.scope_row.set_visible(folder);
        imp.one_level_switch.set_visible(folder);
        imp.one_level_switch
            .set_active(ace.flags & annuaire_codecs::sd::NO_PROPAGATE_INHERIT_ACE != 0);
        let texts: Vec<String> = levels().iter().map(|l| shv::file_level_text(*l)).collect();
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        imp.level_row.set_model(Some(&gtk::StringList::new(&texts)));
        let mask = shv::file_mask(ace.mask());
        imp.mask.set(mask);
        for bit in shv::FINE_RIGHTS {
            let row = adw::SwitchRow::builder()
                .title(shv::fine_right_text(bit, folder))
                .active(mask & bit != 0)
                .build();
            let weak = dialog.downgrade();
            row.connect_active_notify(move |_| {
                if let Some(dialog) = weak.upgrade() {
                    dialog.right_toggled();
                }
            });
            imp.rights_group.add(&row);
            imp.rights.borrow_mut().push((bit, row));
        }
        *imp.original.borrow_mut() = Some(ace);
        *imp.chosen.borrow_mut() = Some(chosen);
        dialog.show_level();
        imp.updating.set(false);
        dialog
    }

    fn show_level(&self) {
        let imp = self.imp();
        let level = shv::file_level(imp.mask.get());
        let index = levels().iter().position(|l| *l == level).unwrap_or(0);
        imp.level_row.set_selected(index as u32);
    }

    fn level_chosen(&self) {
        let imp = self.imp();
        if imp.updating.get() {
            return;
        }
        let Some(level) = levels().get(imp.level_row.selected() as usize).copied() else {
            return;
        };
        if level == FileLevel::Special {
            return;
        }
        let mask = shv::file_level_mask(level);
        imp.mask.set(mask);
        imp.updating.set(true);
        for (bit, row) in imp.rights.borrow().iter() {
            row.set_active(mask & bit != 0);
        }
        imp.updating.set(false);
    }

    fn right_toggled(&self) {
        let imp = self.imp();
        if imp.updating.get() {
            return;
        }
        let mut mask = imp.mask.get() & shv::SYNCHRONIZE;
        for (bit, row) in imp.rights.borrow().iter() {
            if row.is_active() {
                mask |= bit;
            }
        }
        if mask & !shv::SYNCHRONIZE != 0 {
            mask |= shv::SYNCHRONIZE;
        }
        imp.mask.set(mask);
        imp.updating.set(true);
        self.show_level();
        imp.updating.set(false);
    }

    /// The entry chosen; the original kept as it is if nothing changed (a generic right
    /// read on Windows stays generic).
    fn entry(&self) -> Option<Ace> {
        let imp = self.imp();
        let original = imp.original.borrow().clone()?;
        let sid = original.sid()?;
        let folder = imp.folder.get();
        let scope = if folder {
            shv::SCOPES
                .get(imp.scope_row.selected() as usize)
                .copied()
                .unwrap_or(shv::Scope::FolderSubfoldersFiles)
        } else {
            shv::Scope::ThisFolder
        };
        let one_level = folder && imp.one_level_switch.is_active();
        let audit = imp.audit.get();
        let mut ace = shv::entry_ace(
            !audit && imp.type_row.selected() == 1,
            imp.mask.get(),
            scope,
            one_level,
            &sid,
        )?;
        if audit {
            use annuaire_codecs::sd::{FAILED_ACCESS_ACE, SUCCESSFUL_ACCESS_ACE, SYSTEM_AUDIT};
            ace.ace_type = SYSTEM_AUDIT;
            ace.flags |= match imp.type_row.selected() {
                1 => FAILED_ACCESS_ACE,
                2 => SUCCESSFUL_ACCESS_ACE | FAILED_ACCESS_ACE,
                _ => SUCCESSFUL_ACCESS_ACE,
            };
        }
        let same = ace.ace_type == original.ace_type
            && ace.flags == original.flags & !annuaire_codecs::sd::INHERITED_ACE
            && ace.mask() == shv::file_mask(original.mask());
        Some(if same && !original.is_inherited() {
            original
        } else {
            ace
        })
    }

    fn confirm(&self) {
        let Some(ace) = self.entry() else { return };
        let chosen = self.imp().chosen.take();
        self.close();
        if let Some(chosen) = chosen {
            chosen(ace);
        }
    }
}

// --- The owner ------------------------------------------------------------------------------------

/// What follows the dialog of the owner: the SID chosen and, if known, its name.
type OwnerChosen = Box<dyn FnOnce(Sid, Option<String>)>;

mod owner_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-proprietaire-ntfs.ui")]
    pub struct OwnerDialog {
        #[template_child]
        pub myself_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub principal_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub myself: Cell<Option<Sid>>,
        pub search: RefCell<Option<Rc<Feed>>>,
        pub received: RefCell<Vec<(ElementView, Option<Sid>)>>,
        pub chosen: RefCell<Option<OwnerChosen>>,
    }

    impl std::fmt::Debug for OwnerDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("OwnerDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for OwnerDialog {
        const NAME: &'static str = "AnnuaireDialogueProprietaireNtfs";
        type Type = super::OwnerDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::OwnerDialog>(&[
                ("myself", |d, _| {
                    if let Some(sid) = d.imp().myself.get() {
                        d.choose(sid, None);
                    }
                    None
                }),
                ("administrators", |d, _| {
                    if let Ok(sid) = "S-1-5-32-544".parse::<Sid>() {
                        d.choose(sid, None);
                    }
                    None
                }),
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for OwnerDialog {}
    impl WidgetImpl for OwnerDialog {}

    impl AdwDialogImpl for OwnerDialog {
        fn closed(&self) {
            if let Some(feed) = self.search.take() {
                feed.cancel();
            }
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// The owner of a file or folder (`AnnuaireDialogueProprietaireNtfs`).
    pub struct OwnerDialog(ObjectSubclass<owner_imp::OwnerDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl OwnerDialog {
    pub fn new(
        source: Arc<dyn Source>,
        connection: Option<Arc<annuaire_core::connection::Connection>>,
        chosen: OwnerChosen,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.source.set(source);
        *imp.chosen.borrow_mut() = Some(chosen);
        imp.myself_row.set_sensitive(false);
        imp.myself_row.set_subtitle(&tr("Searching…"));
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(dialog) = weak.upgrade() {
                dialog.picked(row);
            }
        });
        // The SID of the account bound: `whoami`, then its `objectSid`.
        let weak = dialog.downgrade();
        glib::spawn_future_local(async move {
            let found = gio::spawn_blocking(move || {
                connection.map(|c| annuaire_core::security::own_sid(&c))
            })
            .await;
            let Some(dialog) = weak.upgrade() else { return };
            let imp = dialog.imp();
            match found {
                Ok(Some(Ok(Some(sid)))) => {
                    imp.myself.set(Some(sid));
                    imp.myself_row.set_subtitle(&sid.to_string());
                    imp.myself_row.set_sensitive(true);
                }
                _ => imp
                    .myself_row
                    .set_subtitle(&tr("The account in use cannot be read in the directory.")),
            }
        });
        dialog
    }

    fn source(&self) -> Arc<dyn Source> {
        self.imp().source.get().expect("set by new").clone()
    }

    fn choose(&self, sid: Sid, name: Option<String>) {
        let chosen = self.imp().chosen.take();
        self.close();
        if let Some(chosen) = chosen {
            chosen(sid, name);
        }
    }

    fn search(&self) {
        let imp = self.imp();
        if let Some(feed) = imp.search.take() {
            feed.cancel();
        }
        empty(&imp.candidates_list);
        imp.received.borrow_mut().clear();
        imp.candidates_list.set_visible(false);
        let Some(filter) = sv::delegates_filter(&imp.principal_entry.text()) else {
            imp.candidates_count.set_label("");
            return;
        };
        imp.candidates_count.set_label(&tr("Searching…"));
        let source = self.source();
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = deliver_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                for item in &items {
                    let view = sheet::element_from_item(item);
                    if imp.received.borrow().len() < MAX_RESULTS {
                        imp.candidates_list
                            .append(&candidate_row(&view, &tr("Choose")));
                    }
                    imp.received.borrow_mut().push((view, object_sid(item)));
                }
                imp.candidates_list
                    .set_visible(!imp.received.borrow().is_empty());
                let n = imp.received.borrow().len();
                imp.candidates_count.set_label(&count_text(n, false));
            },
            move |error| {
                let Some(dialog) = finish_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                imp.search.take();
                match error {
                    Some(error) => imp
                        .candidates_count
                        .set_label(&errors::search_problem(&error, &domain).message),
                    None => {
                        let n = imp.received.borrow().len();
                        imp.candidates_count.set_label(&count_text(n, true));
                    }
                }
            },
        );
        *imp.search.borrow_mut() = Some(feed);
    }

    fn picked(&self, row: &gtk::ListBoxRow) {
        let dn = row.widget_name().to_string();
        let found = self
            .imp()
            .received
            .borrow()
            .iter()
            .find(|(v, _)| v.dn == dn)
            .cloned();
        let Some((view, sid)) = found else { return };
        if let Some(sid) = sid {
            self.choose(sid, Some(view.title));
            return;
        }
        // The local copy may not carry the SID: it is read on the DC.
        let (source, weak, target) = (self.source(), self.downgrade(), view.dn.clone());
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || source.record(&target, &["objectSid"])).await;
            let Some(dialog) = weak.upgrade() else { return };
            let sid = match read {
                Ok(Ok(Some(record))) => record
                    .values("objectSid")
                    .first()
                    .and_then(|v| Sid::decode(v).ok()),
                _ => None,
            };
            match sid {
                Some(sid) => dialog.choose(sid, Some(view.title)),
                None => writes::show_error(&dialog, &tr("Unreadable SID"), &view.title, ""),
            }
        });
    }
}
