// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Dialog of a DNS record (J3.4, `annuaire.ui.dns_enregistrement`): addition or
//! modification. Structure in `dialogue-enregistrement-dns.blp`.
//!
//! Only the fields of the type chosen are shown; the input is checked at each keystroke by
//! the core (`dns_write`), and « Continue » stays greyed while it is invalid. Continue reads
//! the name on the DC of the writes (`dns_write::build`): an inconsistency (CNAME not alone,
//! record already there or gone) shows here, otherwise the common preview opens
//! (`writes::propose`), with the new attempt in case of conflict on the SOA. The dialog
//! closes when the write succeeded.
//!
//! When adding an A or an AAAA, « Also create the reverse pointer » adds the PTR in the most
//! precise reverse zone that covers the address, if there is one (as the Windows DNS
//! console): one changeset, on two zones.

use std::net::IpAddr;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::dns_record::{self, Record, RecordData};
use annuaire_core::changes::Issue;
use annuaire_core::dns::{ROOT, Zone, fqdn};
use annuaire_core::dns_write::{self, DnsError, Request};
use gtk::{gio, glib};

use crate::catalog::AppCatalog;
use crate::dns_views as dv;
use crate::i18n::{fill, tr};
use crate::writes::{self, Options};

/// The types of the list, in its order (`TYPES`).
const TYPES: [u16; 7] = dns_write::WRITTEN_TYPES;

/// Fields of each type (`_CHAMPS`): address, priority, weight, port, target, text.
fn fields(rtype: u16) -> [bool; 6] {
    match rtype {
        dns_record::A | dns_record::AAAA => [true, false, false, false, false, false],
        dns_record::CNAME | dns_record::PTR => [false, false, false, false, true, false],
        dns_record::MX => [false, true, false, false, true, false],
        dns_record::SRV => [false, true, true, true, true, false],
        _ => [false, false, false, false, false, true],
    }
}

/// Title of the target field (`_TITRES_CIBLE`).
fn target_title(rtype: u16) -> Option<String> {
    Some(match rtype {
        dns_record::CNAME => tr("Target name (the name this one is an alias of)"),
        dns_record::PTR => tr("Host name pointed to"),
        dns_record::MX => tr("Mail server"),
        dns_record::SRV => tr("Host offering the service"),
        _ => return None,
    })
}

mod imp {
    use std::cell::{Cell, OnceCell, RefCell};

    use adw::subclass::prelude::*;
    use annuaire_core::dns::Zone;
    use gtk::glib;

    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-enregistrement-dns.ui")]
    pub struct RecordDialog {
        #[template_child]
        pub cancel_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub confirm_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub confirm_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub message: TemplateChild<adw::Banner>,
        #[template_child]
        pub name_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub type_combo: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub data_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub address_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub priority_entry: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub weight_entry: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub port_entry: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub target_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub text_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub ttl_entry: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub ptr_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub ptr_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub state: TemplateChild<gtk::Label>,
        pub zone: OnceCell<Zone>,
        pub zones: RefCell<Vec<Zone>>,
        /// Raw value shown of the record modified; None: addition.
        pub value: RefCell<Option<Vec<u8>>>,
        pub ready: Cell<bool>,
    }

    impl std::fmt::Debug for RecordDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RecordDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for RecordDialog {
        const NAME: &'static str = "AnnuaireDialogueEnregistrementDns";
        type Type = super::RecordDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::RecordDialog>(&[
                ("cancel", |d, _| {
                    adw::prelude::AdwDialogExt::close(d);
                    None
                }),
                ("confirm", |d, _| {
                    d.validate();
                    None
                }),
                ("type_changed", |d, _| {
                    d.type_changed();
                    None
                }),
                ("changed", |d, _| {
                    d.changed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for RecordDialog {}
    impl WidgetImpl for RecordDialog {}
    impl AdwDialogImpl for RecordDialog {}
}

glib::wrapper! {
    /// Addition or modification of a DNS record (`AnnuaireDialogueEnregistrementDns`).
    pub struct RecordDialog(ObjectSubclass<imp::RecordDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl RecordDialog {
    /// Addition in `zone` (at the name `name` proposed), or modification of `value`, raw
    /// value shown of `name` (the one removed will be read again on the DC).
    pub fn new(zone: &Zone, zones: Vec<Zone>, name: &str, value: Option<Vec<u8>>) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.zone.set(zone.clone());
        *imp.zones.borrow_mut() = zones;
        imp.name_entry
            .set_text(if name == ROOT { "" } else { name });
        if let Some(value) = &value {
            dialog.fill_from(value);
        }
        let editing = value.is_some();
        *imp.value.borrow_mut() = value;
        imp.data_group
            .set_description(Some(&fill(&tr("Zone {zone}"), &[("zone", &zone.name)])));
        imp.ready.set(true);
        dialog.type_changed();
        // Focus on the first field to fill: the name when adding, the data when editing.
        let first: gtk::Widget = if editing {
            dialog.first_field()
        } else {
            imp.name_entry.clone().upcast()
        };
        dialog.set_focus(Some(&first));
        dialog
    }

    fn zone(&self) -> &Zone {
        self.imp().zone.get().expect("set by new")
    }

    fn rtype(&self) -> u16 {
        let selected = usize::try_from(self.imp().type_combo.selected()).unwrap_or(0);
        TYPES.get(selected).copied().unwrap_or(dns_record::A)
    }

    fn first_field(&self) -> gtk::Widget {
        let imp = self.imp();
        let [address, priority, _, _, target, text] = fields(self.rtype());
        if address {
            imp.address_entry.clone().upcast()
        } else if priority {
            imp.priority_entry.clone().upcast()
        } else if target {
            imp.target_entry.clone().upcast()
        } else if text {
            imp.text_entry.clone().upcast()
        } else {
            imp.ttl_entry.clone().upcast()
        }
    }

    /// Modification: name and type fixed, fields filled from the value shown (`_remplir`).
    fn fill_from(&self, value: &[u8]) {
        let imp = self.imp();
        let Ok(e) = Record::decode(value) else { return };
        self.set_title(&fill(
            &tr("Edit the {type} Record"),
            &[("type", &e.type_name())],
        ));
        imp.name_entry.set_editable(false);
        imp.name_entry
            .set_tooltip_text(Some(&tr("The name of a record cannot be changed.")));
        if let Some(index) = TYPES.iter().position(|t| *t == e.rtype) {
            imp.type_combo
                .set_selected(u32::try_from(index).unwrap_or(0));
        }
        imp.type_combo.set_sensitive(false);
        imp.ttl_entry.set_value(f64::from(e.ttl));
        match &e.data {
            RecordData::Address(address) => imp.address_entry.set_text(&address.to_string()),
            RecordData::Name(target) => imp.target_entry.set_text(target),
            RecordData::Mx { preference, target } => {
                imp.priority_entry.set_value(f64::from(*preference));
                imp.target_entry.set_text(target);
            }
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                imp.priority_entry.set_value(f64::from(*priority));
                imp.weight_entry.set_value(f64::from(*weight));
                imp.port_entry.set_value(f64::from(*port));
                imp.target_entry.set_text(target);
            }
            RecordData::Txt(_) => imp.text_entry.set_text(&e.data_text().unwrap_or_default()),
            _ => {}
        }
    }

    // --- Input ---------------------------------------------------------------------------

    /// `type_changed`.
    fn type_changed(&self) {
        let imp = self.imp();
        let rtype = self.rtype();
        let shown = fields(rtype);
        for (row, visible) in [
            imp.address_entry.clone().upcast::<gtk::Widget>(),
            imp.priority_entry.clone().upcast(),
            imp.weight_entry.clone().upcast(),
            imp.port_entry.clone().upcast(),
            imp.target_entry.clone().upcast(),
            imp.text_entry.clone().upcast(),
        ]
        .into_iter()
        .zip(shown)
        {
            row.set_visible(visible);
        }
        if let Some(title) = target_title(rtype) {
            imp.target_entry.set_title(&title);
        }
        imp.address_entry.set_title(&if rtype == dns_record::AAAA {
            tr("IPv6 address")
        } else {
            tr("IPv4 address")
        });
        imp.ptr_group.set_visible(
            imp.value.borrow().is_none() && (rtype == dns_record::A || rtype == dns_record::AAAA),
        );
        self.changed();
    }

    fn spin(row: &adw::SpinRow) -> u16 {
        // The adjustments are bounded to 0..=65535.
        u16::try_from(row.value().round() as i64).unwrap_or(u16::MAX)
    }

    /// `_donnees`.
    fn data(&self) -> Result<RecordData, DnsError> {
        let imp = self.imp();
        let rtype = self.rtype();
        let target = imp.target_entry.text().to_string();
        match rtype {
            dns_record::A | dns_record::AAAA => {
                let text = imp.address_entry.text().trim().to_owned();
                let address: IpAddr = text
                    .parse()
                    .map_err(|_| DnsError::InvalidAddress { text: text.clone() })?;
                dns_write::verify_data(rtype, &RecordData::Address(address))
            }
            dns_record::CNAME | dns_record::PTR => {
                dns_write::verify_data(rtype, &RecordData::Name(target))
            }
            dns_record::MX => dns_write::verify_data(
                rtype,
                &RecordData::Mx {
                    preference: Self::spin(&imp.priority_entry),
                    target,
                },
            ),
            dns_record::SRV => dns_write::verify_data(
                rtype,
                &RecordData::Srv {
                    priority: Self::spin(&imp.priority_entry),
                    weight: Self::spin(&imp.weight_entry),
                    port: Self::spin(&imp.port_entry),
                    target,
                },
            ),
            _ => dns_write::verify_data(
                rtype,
                &RecordData::Txt(dns_write::read_txt(&imp.text_entry.text())?),
            ),
        }
    }

    /// Reverse zone of the address typed (A, AAAA), and relative name of the PTR
    /// (`_inverse`).
    fn reverse(&self) -> Option<(Zone, String)> {
        let address: IpAddr = self.imp().address_entry.text().trim().parse().ok()?;
        dns_write::reverse_zone(&self.imp().zones.borrow(), address)
    }

    /// What the input asks (`demandes`).
    fn requests(&self) -> Result<Vec<Request>, DnsError> {
        let imp = self.imp();
        let zone = self.zone().clone();
        let name = dns_write::relative_name(&zone.name, &imp.name_entry.text())?;
        let data = self.data()?;
        #[allow(clippy::cast_possible_truncation)]
        let ttl = dns_write::verify_ttl(imp.ttl_entry.value().round() as i64)?;
        let rtype = self.rtype();
        if let Some(old) = imp.value.borrow().clone() {
            return Ok(vec![Request::Modify {
                zone,
                name,
                old,
                rtype,
                data,
                ttl,
            }]);
        }
        let mut requests = vec![Request::Add {
            zone: zone.clone(),
            name: name.clone(),
            rtype,
            data,
            ttl,
        }];
        if imp.ptr_switch.is_active() {
            if let Some((reverse, pointer)) = self.reverse() {
                requests.push(Request::Add {
                    zone: reverse,
                    name: pointer,
                    rtype: dns_record::PTR,
                    data: RecordData::Name(fqdn(&zone.name, &name)),
                    ttl,
                });
            }
        }
        Ok(requests)
    }

    /// `changed`.
    fn changed(&self) {
        let imp = self.imp();
        if !imp.ready.get() {
            return;
        }
        imp.message.set_revealed(false);
        let rtype = self.rtype();
        if (rtype == dns_record::A || rtype == dns_record::AAAA) && imp.value.borrow().is_none() {
            let reverse = self.reverse();
            imp.ptr_switch.set_sensitive(reverse.is_some());
            match reverse {
                None => {
                    imp.ptr_switch.set_active(false);
                    imp.ptr_switch
                        .set_subtitle(&tr("No reverse zone in the directory covers this address."));
                }
                Some((zone, name)) => imp.ptr_switch.set_subtitle(&fill(
                    &tr("{nom} in the {zone} zone"),
                    &[("nom", &name), ("zone", &zone.name)],
                )),
            }
        }
        match self.requests() {
            Err(error) => {
                imp.state.set_label(&dv::dns_error(&error));
                imp.confirm_button.set_sensitive(false);
            }
            Ok(requests) => {
                imp.state.set_label(&dv::describe_requests(&requests));
                imp.confirm_button.set_sensitive(true);
            }
        }
    }

    // --- Write ---------------------------------------------------------------------------

    /// `confirm`.
    fn validate(&self) {
        let imp = self.imp();
        let requests = match self.requests() {
            Ok(requests) => requests,
            Err(error) => {
                self.error(&dv::dns_error(&error));
                return;
            }
        };
        let Some(context) = writes::context(self) else {
            self.error(&tr("No domain is open."));
            return;
        };
        imp.confirm_stack.set_visible_child_name("attente");
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let (connection, asked) = (context.connection.clone(), requests.clone());
            let built = gio::spawn_blocking(move || {
                dns_write::build(&connection, asked, Arc::new(AppCatalog))
            })
            .await;
            let Some(dialog) = weak.upgrade() else { return };
            dialog.imp().confirm_stack.set_visible_child_name("bouton");
            let changeset = match built {
                Ok(Ok(changeset)) => changeset,
                Ok(Err(dns_write::PrepareError::Dns(error))) => {
                    dialog.error(&dv::dns_error(&error));
                    return;
                }
                Ok(Err(error)) => {
                    let (message, detail) =
                        crate::dns::prepare_message(&error, &context.profile.domain);
                    writes::show_error(&dialog, &tr("Cannot read"), &message, &detail);
                    return;
                }
                Err(_) => return,
            };
            let closing = dialog.downgrade();
            writes::propose(
                &dialog,
                changeset,
                Options {
                    retry: Some(dns_write::rebuild(requests, Arc::new(AppCatalog))),
                    finished: Some(Box::new(move |report| {
                        if report.is_some_and(|r| r.issue == Issue::Applied) {
                            if let Some(dialog) = closing.upgrade() {
                                dialog.close();
                            }
                        }
                    })),
                    ..Options::default()
                },
            );
        });
    }

    fn error(&self, text: &str) {
        let imp = self.imp();
        imp.message.set_title(text);
        imp.message.set_revealed(true);
    }

    /// Fills the fields as the user would (trials): name, type, data, TTL, PTR.
    pub fn trial_fill(&self, name: &str, rtype: &str, data: &str, ptr: bool) {
        let imp = self.imp();
        if !name.is_empty() {
            imp.name_entry.set_text(name);
        }
        if let Some(index) = TYPES
            .iter()
            .position(|t| dns_record::type_name(*t) == rtype)
        {
            imp.type_combo
                .set_selected(u32::try_from(index).unwrap_or(0));
        }
        match self.rtype() {
            dns_record::A | dns_record::AAAA => imp.address_entry.set_text(data),
            dns_record::TXT => imp.text_entry.set_text(data),
            dns_record::CNAME | dns_record::PTR => imp.target_entry.set_text(data),
            _ => {
                let pieces: Vec<&str> = data.split_whitespace().collect();
                if let Some((target, numbers)) = pieces.split_last() {
                    let rows = [&imp.priority_entry, &imp.weight_entry, &imp.port_entry];
                    for (row, n) in rows.iter().zip(numbers) {
                        row.set_value(n.parse().unwrap_or(0.0));
                    }
                    imp.target_entry.set_text(target);
                }
            }
        }
        imp.ptr_switch.set_active(ptr);
        self.changed();
    }

    /// Clicks « Continue » once the input is valid (trials).
    pub fn trial_validate(&self) -> bool {
        if !self.imp().confirm_button.is_sensitive() {
            return false;
        }
        self.validate();
        true
    }

    /// The state line and the banner (trials).
    pub fn trial_state(&self) -> String {
        let imp = self.imp();
        format!(
            "{} | {}",
            imp.state.label(),
            if imp.message.is_revealed() {
                imp.message.title().to_string()
            } else {
                String::new()
            }
        )
    }
}
