// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Hooks for the interface trials (ADR 0019, section 7), inert without their variables:
//! `ANNUAIRE_ESSAI_CAPTURE=FILE.png` renders the window into a PNG once it has been shown for
//! `ANNUAIRE_ESSAI_DELAI` milliseconds (2,000 by default), as `capturer` of the Python trials,
//! without a screenshot of the compositor; `ANNUAIRE_ESSAI_QUITTER=1` then quits.
//! `ANNUAIRE_ESSAI_NOEUD=PATH` (`Labo/Paris`) selects that node of the tree as soon as it is shown (the
//! domain being opened by its action, `win.ouvrir-profil`, over D-Bus) and writes on the
//! standard error the time the table took to be read, and its rows.
//! `ANNUAIRE_ESSAI_RECHERCHE=TEXT` (with `ANNUAIRE_ESSAI_TYPE`, a value of `TypeCherche`) or
//! `ANNUAIRE_ESSAI_REQUETE=NAME` (a value of `Requete`) runs that search once the domain is
//! open, and writes the time of the first rows and of the whole reading.
//! `ANNUAIRE_ESSAI_FICHE=DN` opens the sheet of that object once the domain is open, on the
//! tab `ANNUAIRE_ESSAI_ONGLET` if given (`general`, `compte`, `membres`, `groupes`).
//! `ANNUAIRE_ESSAI_DNS=STEP;;STEP…` runs steps in the DNS window (R4.7, `dns_trial`).
//! `ANNUAIRE_ESSAI_GPO=STEP;;STEP…` runs steps in the « Group Policy » and « Password
//! Policies » windows (R4.8, `gpo_trial`).
//! `ANNUAIRE_ESSAI_FOCUS=1` (with `ANNUAIRE_ESSAI_NOEUD`) opens the sheet of the first row
//! from the table, closes it, then again with the table read anew while the sheet is open,
//! and writes where the focus went back each time (R4.10, `clavier._Focus`).

use std::path::PathBuf;
use std::time::Duration;

use gtk::prelude::*;
use gtk::{glib, graphene};

pub fn arm(window: &crate::window::Window) {
    if let Some(path) = std::env::var("ANNUAIRE_ESSAI_NOEUD")
        .ok()
        .filter(|p| !p.is_empty())
    {
        select_node(window, path);
    }
    // An empty variable is no search; a blank one searches every object of the type.
    let text = std::env::var("ANNUAIRE_ESSAI_RECHERCHE")
        .ok()
        .filter(|t| !t.is_empty());
    let query = std::env::var("ANNUAIRE_ESSAI_REQUETE")
        .ok()
        .filter(|q| !q.is_empty());
    if text.is_some() || query.is_some() {
        run_search(window, text, query);
    }
    if let Some(dn) = std::env::var("ANNUAIRE_ESSAI_FICHE")
        .ok()
        .filter(|d| !d.is_empty())
    {
        open_sheet(window, dn, std::env::var("ANNUAIRE_ESSAI_ONGLET").ok());
    }
    if let Some(name) = std::env::var("ANNUAIRE_ESSAI_DIALOGUE")
        .ok()
        .filter(|a| !a.is_empty())
    {
        let weak = window.downgrade();
        glib::timeout_add_local(Duration::from_millis(200), move || {
            let Some(window) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            if window.source().is_none() {
                return glib::ControlFlow::Continue;
            }
            let _ = gtk::prelude::WidgetExt::activate_action(&window, &format!("win.{name}"), None);
            eprintln!("essai dialogue {name}");
            glib::ControlFlow::Break
        });
    }
    if let Some(how) = std::env::var("ANNUAIRE_ESSAI_ANNULER")
        .ok()
        .filter(|a| !a.is_empty())
    {
        undo_trial(window, how);
    }
    if let Some(steps) = std::env::var("ANNUAIRE_ESSAI_ETAPES")
        .ok()
        .filter(|a| !a.is_empty())
    {
        steps_trial(window, steps.split(";;").map(str::to_owned).collect());
    }
    if let Some(steps) = std::env::var("ANNUAIRE_ESSAI_DNS")
        .ok()
        .filter(|a| !a.is_empty())
    {
        dns_trial(window, steps.split(";;").map(str::to_owned).collect());
    }
    if let Some(steps) = std::env::var("ANNUAIRE_ESSAI_GPO")
        .ok()
        .filter(|a| !a.is_empty())
    {
        gpo_trial(window, steps.split(";;").map(str::to_owned).collect());
    }
    if std::env::var_os("ANNUAIRE_ESSAI_FOCUS").is_some() {
        focus_trial(window);
    }
    if let Some(action) = std::env::var("ANNUAIRE_ESSAI_ACTION")
        .ok()
        .filter(|a| !a.is_empty())
    {
        write_trial(window, action);
    }
    capture_later(window.upcast_ref());
}

/// Steps `action|argument|…`, one after the other once the previous one is over: each built
/// by `annuaire_core::actions` from the objects read on the PDC, proposed, applied once
/// checked; the issue written on the standard error (trial of the actions on the accounts).
/// `ctrl-z`: the last change undone as by Ctrl+Z; `historique`: the most recent entry of the
/// history undone; the preview confirmed once verified.
fn undo_trial(window: &crate::window::Window, how: String) {
    let weak = window.downgrade();
    let mut asked = false;
    glib::timeout_add_local(Duration::from_millis(200), move || {
        let Some(window) = weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        if window.source().is_none() {
            return glib::ControlFlow::Continue;
        }
        if !asked {
            asked = true;
            if how == "historique" {
                let Some(context) = window.write_context() else {
                    return glib::ControlFlow::Break;
                };
                let history = crate::history::HistoryDialog::new(context);
                adw::prelude::AdwDialogExt::present(&history, Some(&window));
                eprintln!("essai historique : {}", history.trial_undo_first());
            } else {
                crate::history::undo_last(&window);
            }
            return glib::ControlFlow::Continue;
        }
        let preview = gtk::Window::list_toplevels().into_iter().find_map(|w| {
            crate::sheet::all_under(&w)
                .into_iter()
                .find_map(|w| w.downcast::<crate::writes::PreviewDialog>().ok())
        });
        let Some(preview) = preview.filter(crate::writes::PreviewDialog::trial_verified) else {
            return glib::ControlFlow::Continue;
        };
        eprintln!("essai annulation : {}", preview.trial_problems());
        eprintln!("essai annulation appliquée : {}", preview.trial_apply());
        glib::ControlFlow::Break
    });
}

fn steps_trial(window: &crate::window::Window, steps: Vec<String>) {
    let weak = window.downgrade();
    glib::timeout_add_local(Duration::from_millis(200), move || {
        let Some(window) = weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        if window.source().is_none() {
            return glib::ControlFlow::Continue;
        }
        // With a node to show, the steps wait for its table: the update in place is tried.
        let node = std::env::var("ANNUAIRE_ESSAI_NOEUD").unwrap_or_default();
        let last = node.rsplit('/').next().unwrap_or_default();
        if !node.is_empty()
            && (window.trial_title().as_deref() != Some(last)
                || !window.trial_rows().is_some_and(|n| n > 0))
        {
            return glib::ControlFlow::Continue;
        }
        run_step(&window, steps.clone(), 0);
        glib::ControlFlow::Break
    });
}

fn run_step(window: &crate::window::Window, steps: Vec<String>, index: usize) {
    use annuaire_core::actions as act;
    let Some(step) = steps.get(index).cloned() else {
        eprintln!("essai étapes : fin");
        return;
    };
    let Some(context) = window.write_context() else {
        return;
    };
    let parts: Vec<String> = step.split('|').map(str::to_owned).collect();
    let weak = window.downgrade();
    glib::spawn_future_local(async move {
        let connection = context.connection.clone();
        let parts_read = parts.clone();
        let built = gtk::gio::spawn_blocking(
            move || -> Result<annuaire_core::changes::Changeset, String> {
                let p = |i: usize| parts_read.get(i).cloned().unwrap_or_default();
                let read = |dns: Vec<String>, sd: bool| {
                    if sd {
                        act::read_descriptors(&connection, &dns)
                    } else {
                        act::read_objects(&connection, &dns, &act::STATE_ATTRIBUTES)
                    }
                    .map_err(|e| format!("{e:?}"))
                };
                let e = |e: act::ActionError| format!("{e:?}");
                match p(0).as_str() {
                    "creer-ou" => act::create_ou(&p(1), &p(2), "").map_err(e),
                    "creer-groupe" => act::create_group(
                        &p(1),
                        &p(2),
                        "",
                        annuaire_codecs::uac::Scope::Global,
                        true,
                        "",
                    )
                    .map_err(e),
                    "creer-utilisateur" => act::create_user(
                        &p(1),
                        &act::NewUser {
                            full_name: p(2),
                            identifier: p(3),
                            password: Some(p(4)),
                            change_at_next_logon: true,
                            enable: true,
                            ..Default::default()
                        },
                    )
                    .map_err(e),
                    "desactiver" => act::enable(&read(vec![p(1)], false)?, false).map_err(e),
                    "activer" => act::enable(&read(vec![p(1)], false)?, true).map_err(e),
                    "mot-de-passe" => {
                        let objects = read(vec![p(1)], false)?;
                        let object = objects.first().ok_or("absent")?;
                        act::reset_password(object, &p(2), true).map_err(e)
                    }
                    "renommer" => {
                        let objects = read(vec![p(1)], false)?;
                        let object = objects.first().ok_or("absent")?;
                        act::rename(object, &p(2), Some(&p(2)), None).map_err(e)
                    }
                    "deplacer" => act::move_to(&read(vec![p(1)], false)?, &p(2)).map_err(e),
                    "proteger" => {
                        let parent = annuaire_core::changes::parent_dn(&p(1)).unwrap_or_default();
                        let objects = read(vec![p(1), parent], true)?;
                        let [ou, parent] = objects.as_slice() else {
                            return Err("absent".into());
                        };
                        act::protect_ou(ou, parent).map_err(e)
                    }
                    "deproteger" => {
                        let objects = read(vec![p(1)], true)?;
                        act::unprotect_ou(objects.first().ok_or("absent")?).map_err(e)
                    }
                    "supprimer" => act::delete(&read(vec![p(1)], false)?).map_err(e),
                    // Remise en état du labo : le refus « supprimer des enfants » posé sur le parent.
                    "retirer-refus-parent" => {
                        let objects = read(vec![p(1)], true)?;
                        let parent = objects.first().ok_or("absent")?;
                        let raw = parent
                            .values(act::SD)
                            .into_iter()
                            .next()
                            .ok_or("sans descripteur")?;
                        let sd = annuaire_codecs::sd::SecurityDescriptor::decode(&raw)
                            .map_err(|x| x.to_string())?;
                        let new = sd.remove_aces(&[act::parent_ace()]);
                        if new == sd {
                            return Ok(annuaire_core::changes::Changeset::default());
                        }
                        let change = annuaire_core::changes::Change::new(
                            act::SD,
                            vec![raw],
                            vec![new.encode().map_err(|x| x.to_string())?],
                        )
                        .map_err(|x| x.to_string())?;
                        let op = annuaire_core::changes::Operation::modify(
                            &parent.dn,
                            vec![change],
                            Some(parent.read.clone()),
                        )
                        .map_err(|x| x.to_string())?;
                        Ok(annuaire_core::changes::Changeset {
                            operations: vec![op],
                            remarks: Vec::new(),
                        })
                    }
                    other => Err(format!("étape inconnue {other}")),
                }
            },
        )
        .await;
        let Some(window) = weak.upgrade() else { return };
        let changeset = match built {
            Ok(Ok(c)) if !c.operations.is_empty() => c,
            other => {
                eprintln!(
                    "essai étape {} : rien à proposer {other:?}",
                    parts.join("|")
                );
                run_step(&window, steps, index + 1);
                return;
            }
        };
        let label = parts.first().cloned().unwrap_or_default();
        let next = window.downgrade();
        let dialog = crate::writes::propose(
            &window,
            changeset,
            crate::writes::Options {
                finished: Some(Box::new(move |report| {
                    eprintln!(
                        "essai étape {label} : {}",
                        report.map_or("rien tenté", |r| r.issue.name())
                    );
                    if let Some(window) = next.upgrade() {
                        let steps = steps.clone();
                        glib::timeout_add_local_once(Duration::from_millis(300), move || {
                            run_step(&window, steps, index + 1);
                        });
                    }
                })),
                ..Default::default()
            },
        );
        let Some(dialog) = dialog else { return };
        glib::timeout_add_local(Duration::from_millis(50), move || {
            if !dialog.trial_verified() {
                return glib::ControlFlow::Continue;
            }
            if !dialog.trial_apply() {
                eprintln!("essai étape refusée : {}", dialog.trial_problems());
                adw::prelude::AdwDialogExt::close(&dialog);
            }
            glib::ControlFlow::Break
        });
    });
}

/// `ATTRIBUTE|DN|VALUE` (empty value: clear), several separated by `;;`: the modifications
/// prepared on the PDC, proposed together, applied once checked; the issue written on the
/// standard error (trial of the writes).
fn write_trial(window: &crate::window::Window, action: String) {
    // `?…`: the preview only, not applied (comparison of the dialogs).
    let (action, apply) = match action.strip_prefix('?') {
        Some(rest) => (rest.to_owned(), false),
        None => (action, true),
    };
    let mut wanted: Vec<(String, String, Vec<Vec<u8>>)> = Vec::new();
    for item in action.split(";;") {
        let mut parts = item.splitn(3, '|');
        let (Some(attribute), Some(dn), Some(value)) = (parts.next(), parts.next(), parts.next())
        else {
            eprintln!("essai écriture : ANNUAIRE_ESSAI_ACTION=attribut|DN|valeur[;;…]");
            return;
        };
        let values = if value.is_empty() {
            Vec::new()
        } else {
            vec![value.as_bytes().to_vec()]
        };
        wanted.push((attribute.to_owned(), dn.to_owned(), values));
    }
    let weak = window.downgrade();
    glib::timeout_add_local(Duration::from_millis(200), move || {
        let Some(window) = weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        let Some(context) = window.write_context() else {
            return glib::ControlFlow::Continue;
        };
        let (wanted, weak) = (wanted.clone(), window.downgrade());
        glib::spawn_future_local(async move {
            let connection = context.connection.clone();
            let prepared = gtk::gio::spawn_blocking(move || {
                let mut operations = Vec::new();
                for (attribute, dn, values) in wanted {
                    // `~attribute`: an outdated version, as if read before another write.
                    let (attribute, stale) = match attribute.strip_prefix('~') {
                        Some(a) => (a.to_owned(), true),
                        None => (attribute, false),
                    };
                    match annuaire_core::writer::prepare_modification(
                        &connection,
                        &dn,
                        vec![(attribute, values)],
                    ) {
                        Ok(Some(mut op)) => {
                            if let (
                                true,
                                annuaire_core::changes::Operation::Modify {
                                    read: Some(read), ..
                                },
                            ) = (stale, &mut op)
                            {
                                read.usn -= 1;
                            }
                            operations.push(op);
                        }
                        Ok(None) => {}
                        Err(e) => return Err(format!("{e:?}")),
                    }
                }
                Ok(operations)
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            let operations = match prepared {
                Ok(Ok(ops)) => ops,
                other => {
                    eprintln!("essai écriture : préparation impossible {other:?}");
                    return;
                }
            };
            let changeset = annuaire_core::changes::Changeset {
                operations,
                remarks: Vec::new(),
            };
            let start = std::time::Instant::now();
            let dialog = crate::writes::propose(
                &window,
                changeset,
                crate::writes::Options {
                    finished: Some(Box::new(move |report| match report {
                        Some(r) => eprintln!(
                            "essai écriture : {} ({} opération(s)) en {:.2} s",
                            r.issue.name(),
                            r.applied.len(),
                            start.elapsed().as_secs_f64()
                        ),
                        None => eprintln!("essai écriture : rien tenté"),
                    })),
                    ..Default::default()
                },
            );
            let Some(dialog) = dialog else { return };
            glib::timeout_add_local(Duration::from_millis(50), move || {
                if !dialog.trial_verified() {
                    return glib::ControlFlow::Continue;
                }
                if !apply {
                    eprintln!("essai écriture : aperçu vérifié, non appliqué");
                    return glib::ControlFlow::Break;
                }
                if !dialog.trial_apply() {
                    eprintln!(
                        "essai écriture : vérification refusée : {}",
                        dialog.trial_problems()
                    );
                }
                glib::ControlFlow::Break
            });
        });
        glib::ControlFlow::Break
    });
}

/// The sheet of `dn` once the domain is open, on the tab `page` if given.
fn open_sheet(window: &crate::window::Window, dn: String, page: Option<String>) {
    let weak = window.downgrade();
    glib::timeout_add_local(Duration::from_millis(100), move || {
        let Some(window) = weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        let Some(source) = window.source() else {
            return glib::ControlFlow::Continue;
        };
        let sheet = crate::sheet::Sheet::new(source, &dn);
        adw::prelude::AdwDialogExt::present(&sheet, Some(&window));
        let start = std::time::Instant::now();
        let (mut shown, group) = (false, page.as_deref() == Some("membres"));
        let page = page.clone();
        let mut loopback = std::env::var("ANNUAIRE_ESSAI_BOUCLE")
            .ok()
            .filter(|c| !c.is_empty());
        let mut loopback_asked = false;
        let dump = std::env::var_os("ANNUAIRE_ESSAI_ATTRIBUTS")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        let mut inputs = std::env::var("ANNUAIRE_ESSAI_SAISIES")
            .ok()
            .filter(|s| !s.is_empty());
        let apply = std::env::var("ANNUAIRE_ESSAI_APPLIQUER").unwrap_or_default();
        let mut waited = 0;
        glib::timeout_add_local(Duration::from_millis(10), move || {
            if !sheet.trial_shown() {
                return glib::ControlFlow::Continue;
            }
            if !shown {
                shown = true;
                // The tab once the object is shown, as a user would choose it.
                if let Some(page) = page.as_deref().filter(|p| !p.is_empty()) {
                    sheet.trial_page(page);
                }
                eprintln!(
                    "essai fiche affichée en {:.3} s",
                    start.elapsed().as_secs_f64()
                );
            }
            if let Some(spec) = inputs.as_deref() {
                // The members are read after the display: the inputs wait for them.
                if group && sheet.trial_members().is_none() {
                    return glib::ControlFlow::Continue;
                }
                if page.as_deref() == Some("attributs") && sheet.trial_attributes().is_none() {
                    return glib::ControlFlow::Continue;
                }
                if page.as_deref() == Some("securite") && sheet.trial_security().is_none() {
                    return glib::ControlFlow::Continue;
                }
                sheet.trial_input(spec);
                inputs = None;
                if !apply.is_empty() {
                    sheet.trial_apply();
                }
                return glib::ControlFlow::Continue;
            }
            if apply == "2" {
                // Confirms the preview once verified.
                // The preview of « Apply », or of a write of the « Security » tab.
                let preview = sheet.trial_preview().or_else(|| {
                    gtk::Window::list_toplevels().into_iter().find_map(|w| {
                        crate::sheet::all_under(&w)
                            .into_iter()
                            .find_map(|w| w.downcast::<crate::writes::PreviewDialog>().ok())
                    })
                });
                let Some(preview) = preview else {
                    waited += 1;
                    return if waited < 1000 {
                        glib::ControlFlow::Continue
                    } else {
                        glib::ControlFlow::Break
                    };
                };
                if !preview.trial_verified() {
                    return glib::ControlFlow::Continue;
                }
                eprintln!("essai aperçu : {}", preview.trial_problems());
                let applied = preview.trial_apply();
                eprintln!("essai fiche appliquée : {applied}");
                return glib::ControlFlow::Break;
            }
            if let Some(path) = dump.as_ref() {
                if let Some(computer) = loopback.take() {
                    // Once the policy of the account is shown, the one on the computer.
                    if sheet.trial_policy().is_none() {
                        loopback = Some(computer);
                        return glib::ControlFlow::Continue;
                    }
                    sheet.trial_loopback(&computer);
                    loopback_asked = true;
                    return glib::ControlFlow::Continue;
                }
                if loopback_asked
                    && sheet
                        .trial_policy()
                        .is_some_and(|l| l.get(2).is_some_and(|t| t.contains('…')))
                {
                    return glib::ControlFlow::Continue;
                }
                let lines = match page.as_deref() {
                    Some("securite") => sheet.trial_security(),
                    Some("strategie") => sheet.trial_policy(),
                    _ => sheet.trial_attributes(),
                };
                let Some(lines) = lines else {
                    return glib::ControlFlow::Continue;
                };
                let written = std::fs::write(path, lines.join("\n") + "\n");
                eprintln!(
                    "essai attributs : {} lignes en {:.3} s ({})",
                    lines.len(),
                    start.elapsed().as_secs_f64(),
                    path.display()
                );
                if let Err(e) = written {
                    eprintln!("essai attributs : {e}");
                }
                return glib::ControlFlow::Break;
            }
            if !group {
                return glib::ControlFlow::Break;
            }
            let Some(members) = sheet.trial_members() else {
                return glib::ControlFlow::Continue;
            };
            eprintln!(
                "essai membres : {members} en {:.3} s",
                start.elapsed().as_secs_f64()
            );
            glib::ControlFlow::Break
        });
        glib::ControlFlow::Break
    });
}

fn run_search(window: &crate::window::Window, text: Option<String>, query: Option<String>) {
    use annuaire_core::queries::{Kind, Query, State};
    let kind = std::env::var("ANNUAIRE_ESSAI_TYPE")
        .ok()
        .and_then(|k| Kind::from_name(&k))
        .unwrap_or(Kind::All);
    let weak = window.downgrade();
    let mut started: Option<std::time::Instant> = None;
    let mut first: Option<f64> = None;
    glib::timeout_add_local(Duration::from_millis(20), move || {
        let Some(window) = weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        let Some(start) = started else {
            if window.source().is_some() {
                let bar = window.search_bar();
                if let Some(query) = query.as_deref().and_then(Query::from_name) {
                    bar.run_query(query, 180);
                } else {
                    bar.search(text.as_deref().unwrap_or(""), kind, State::All);
                }
                started = Some(std::time::Instant::now());
            }
            return glib::ControlFlow::Continue;
        };
        if first.is_none() && window.trial_shown_rows() > 0 {
            first = Some(start.elapsed().as_secs_f64());
        }
        match window.trial_rows() {
            Some(rows) if start.elapsed() > Duration::from_millis(100) => {
                eprintln!(
                    "essai recherche : {rows} lignes, premières en {:.2} s, toutes en {:.2} s",
                    first.unwrap_or(0.0),
                    start.elapsed().as_secs_f64()
                );
                glib::ControlFlow::Break
            }
            _ => glib::ControlFlow::Continue,
        }
    });
}

fn select_node(window: &crate::window::Window, name: String) {
    let weak = window.downgrade();
    let mut started: Option<std::time::Instant> = None;
    glib::timeout_add_local(Duration::from_millis(100), move || {
        let Some(window) = weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        match started {
            None => {
                if window.trial_select(&name) {
                    started = Some(std::time::Instant::now());
                }
                glib::ControlFlow::Continue
            }
            Some(start) => match window.trial_rows() {
                Some(rows) if start.elapsed() > Duration::from_millis(200) => {
                    eprintln!(
                        "essai {name} : {rows} lignes en {:.2} s",
                        start.elapsed().as_secs_f64()
                    );
                    glib::ControlFlow::Break
                }
                _ => glib::ControlFlow::Continue,
            },
        }
    });
}

/// The focus back in the table after a dialog opened from it (`ANNUAIRE_ESSAI_FOCUS`).
fn focus_trial(window: &crate::window::Window) {
    let weak = window.downgrade();
    glib::spawn_future_local(async move {
        for refresh in [false, true] {
            let Some(window) = weak.upgrade() else { return };
            if until(LIMIT, || window.trial_rows().filter(|n| *n > 0))
                .await
                .is_none()
            {
                eprintln!("essai focus : tableau vide");
                return;
            }
            glib::timeout_future(Duration::from_millis(300)).await;
            window.trial_open_from_table();
            let Some(sheet) = until(LIMIT, find_shown::<crate::sheet::Sheet>).await else {
                eprintln!("essai focus : pas de fiche");
                return;
            };
            glib::timeout_future(Duration::from_millis(500)).await;
            if refresh {
                window.trial_refresh();
                let _ = until(LIMIT, || window.trial_rows().filter(|n| *n > 0)).await;
            }
            adw::prelude::AdwDialogExt::close(&sheet);
            glib::timeout_future(Duration::from_millis(500)).await;
            eprintln!(
                "essai focus (tableau relu : {refresh}) : {}",
                window.trial_focus()
            );
        }
    });
}

fn capture_later(window: &gtk::Window) {
    let Some(path) = std::env::var_os("ANNUAIRE_ESSAI_CAPTURE").map(PathBuf::from) else {
        return;
    };
    let delay = std::env::var("ANNUAIRE_ESSAI_DELAI")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);
    let quit = std::env::var_os("ANNUAIRE_ESSAI_QUITTER").is_some();
    let weak = window.downgrade();
    glib::timeout_add_local_once(Duration::from_millis(delay), move || {
        let Some(window) = weak.upgrade() else { return };
        match capture(&window, &path) {
            Ok(()) => eprintln!("capture {}", path.display()),
            Err(e) => eprintln!("capture {}: {e}", path.display()),
        }
        if quit {
            window.close();
        }
    });
}

fn capture(window: &gtk::Window, path: &std::path::Path) -> Result<(), String> {
    let (width, height) = (window.width(), window.height());
    let paintable = gtk::WidgetPaintable::new(Some(window));
    let snapshot = gtk::Snapshot::new();
    paintable.snapshot(&snapshot, f64::from(width), f64::from(height));
    let node = snapshot.to_node().ok_or("nothing drawn yet")?;
    let renderer = window.renderer().ok_or("no renderer")?;
    #[allow(clippy::cast_precision_loss)] // window sizes are far below 2^24
    let area = graphene::Rect::new(0.0, 0.0, width as f32, height as f32);
    let texture = renderer.render_texture(node, Some(&area));
    texture.save_to_png(path).map_err(|e| e.to_string())
}

// --- DNS (R4.7) ---------------------------------------------------------------------------

/// Waits for `f` to give a value, `limit` at most, letting the loop run.
async fn until<T>(limit: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = std::time::Instant::now();
    loop {
        if let Some(value) = f() {
            return Some(value);
        }
        if start.elapsed() > limit {
            return None;
        }
        glib::timeout_future(Duration::from_millis(10)).await;
    }
}

/// The first widget of type `T` mapped (shown on screen) in a window of the application.
fn find_shown<T: IsA<gtk::Widget>>() -> Option<T> {
    gtk::Window::list_toplevels().into_iter().find_map(|w| {
        crate::sheet::all_under(&w)
            .into_iter()
            .filter(WidgetExt::is_mapped)
            .find_map(|w| w.downcast::<T>().ok())
    })
}

/// The first widget of type `T` shown in a window of the application.
fn find<T: IsA<gtk::Widget>>() -> Option<T> {
    gtk::Window::list_toplevels().into_iter().find_map(|w| {
        crate::sheet::all_under(&w)
            .into_iter()
            .find_map(|w| w.downcast::<T>().ok())
    })
}

const LIMIT: Duration = Duration::from_secs(120);

/// Applies the preview once verified; the time from `start` to the verification.
async fn confirm(start: std::time::Instant, what: &str) -> bool {
    let Some(preview) = until(LIMIT, || {
        find::<crate::writes::PreviewDialog>().filter(crate::writes::PreviewDialog::trial_verified)
    })
    .await
    else {
        eprintln!("essai dns {what} : pas d'aperçu");
        return false;
    };
    eprintln!(
        "essai dns {what} : aperçu vérifié en {:.3} s : {}",
        start.elapsed().as_secs_f64(),
        preview.trial_problems().replace('\n', " | ")
    );
    let applied = preview.trial_apply();
    if !applied {
        eprintln!("essai dns {what} : non appliqué");
    }
    applied
}

/// Waits for the reading again after a write: the window shows `name` and selects the line
/// `data` (None: no line selected, a name gone in tombstone).
async fn reread(
    dns: &crate::dns::DnsWindow,
    start: std::time::Instant,
    name: &str,
    data: Option<&str>,
) {
    let shown = until(LIMIT, || {
        let (title, _, _) = dns.trial_table()?;
        let selected = dns.trial_selected();
        let right = match data {
            Some(d) => title == name && selected.as_deref() == Some(d),
            None => find::<crate::writes::PreviewDialog>().is_none() && selected.is_none(),
        };
        right.then_some(title)
    })
    .await;
    eprintln!(
        "essai dns relu : {} en {:.3} s",
        shown.unwrap_or_else(|| "délai dépassé".into()),
        start.elapsed().as_secs_f64()
    );
}

async fn show_name(dns: &crate::dns::DnsWindow, zone: &str, name: &str) -> bool {
    let full = if name == "@" {
        zone.to_owned()
    } else {
        format!("{name}.{zone}")
    };
    let start = std::time::Instant::now();
    let done = until(LIMIT, || {
        if dns
            .trial_table()
            .is_some_and(|(title, _, _)| title.eq_ignore_ascii_case(&full))
        {
            return Some(());
        }
        dns.trial_select(zone, name);
        None
    })
    .await;
    let Some(()) = done else {
        eprintln!("essai dns nom : {full} introuvable");
        return false;
    };
    if let Some((title, summary, lines)) = dns.trial_table() {
        eprintln!(
            "essai dns nom : {title} en {:.3} s — {summary}",
            start.elapsed().as_secs_f64()
        );
        for line in lines {
            eprintln!("essai dns ligne : {line}");
        }
    }
    true
}

#[allow(clippy::too_many_lines)]
fn dns_trial(window: &crate::window::Window, steps: Vec<String>) {
    let weak = window.downgrade();
    glib::spawn_future_local(async move {
        let mut dns: Option<crate::dns::DnsWindow> = None;
        for step in steps {
            let Some(window) = weak.upgrade() else { return };
            let p: Vec<&str> = step.split('|').collect();
            let arg = |i: usize| p.get(i).copied().unwrap_or_default();
            let start = std::time::Instant::now();
            match arg(0) {
                "domaine" => {
                    let _ = WidgetExt::activate_action(
                        &window,
                        "win.ouvrir-profil",
                        Some(&arg(1).to_variant()),
                    );
                    if until(LIMIT, || window.source()).await.is_none() {
                        eprintln!("essai dns : domaine non ouvert");
                        return;
                    }
                    eprintln!(
                        "essai dns domaine ouvert en {:.3} s",
                        start.elapsed().as_secs_f64()
                    );
                }
                "dns" => {
                    let _ = WidgetExt::activate_action(&window, "win.dns", None);
                    dns = until(LIMIT, || window.imp_dns()).await;
                    let ready = until(LIMIT, || {
                        dns.as_ref().filter(|d| d.trial_ready()).map(|_| ())
                    })
                    .await;
                    eprintln!(
                        "essai dns zones : {} en {:.3} s",
                        ready.is_some(),
                        start.elapsed().as_secs_f64()
                    );
                }
                "nom" => {
                    let Some(d) = dns.as_ref() else { return };
                    if !show_name(d, arg(1), arg(2)).await {
                        return;
                    }
                }
                "ajouter" | "modifier" => {
                    let Some(d) = dns.as_ref() else { return };
                    // A name added is typed in the dialog, opened from its zone.
                    let shown = if arg(0) == "ajouter" { "@" } else { arg(2) };
                    if !show_name(d, arg(1), shown).await {
                        return;
                    }
                    let (data, rtype) = if arg(0) == "ajouter" {
                        let _ = WidgetExt::activate_action(d, "dns.ajouter", None);
                        (arg(4), arg(3))
                    } else {
                        if !d.trial_select_line(arg(3)) {
                            eprintln!("essai dns : ligne {} introuvable", arg(3));
                            return;
                        }
                        let _ = WidgetExt::activate_action(d, "dns.modifier", None);
                        (arg(4), "")
                    };
                    let Some(dialog) = until(LIMIT, find::<crate::dns_record::RecordDialog>).await
                    else {
                        eprintln!("essai dns : pas de dialogue");
                        return;
                    };
                    let name = if arg(0) == "ajouter" { arg(2) } else { "" };
                    dialog.trial_fill(name, rtype, data, arg(5) == "ptr");
                    eprintln!(
                        "essai dns saisie : {}",
                        dialog.trial_state().replace('\n', " | ")
                    );
                    let start = std::time::Instant::now();
                    if !dialog.trial_validate() {
                        eprintln!("essai dns : « Continuer » grisé");
                        return;
                    }
                    if !confirm(start, arg(0)).await {
                        eprintln!("essai dns dialogue : {}", dialog.trial_state());
                        return;
                    }
                    let start = std::time::Instant::now();
                    let full = if arg(2) == "@" {
                        arg(1).to_owned()
                    } else {
                        format!("{}.{}", arg(2), arg(1))
                    };
                    reread(d, start, &full, Some(data)).await;
                }
                "supprimer" => {
                    let Some(d) = dns.as_ref() else { return };
                    if !show_name(d, arg(1), arg(2)).await {
                        return;
                    }
                    if !d.trial_select_line(arg(3)) {
                        eprintln!("essai dns : ligne {} introuvable", arg(3));
                        return;
                    }
                    let _ = WidgetExt::activate_action(d, "dns.supprimer", None);
                    if !confirm(start, "supprimer").await {
                        return;
                    }
                    reread(d, std::time::Instant::now(), "", None).await;
                }
                "annuler" => {
                    let Some(d) = dns.as_ref() else { return };
                    let _ = WidgetExt::activate_action(d, "dns.annuler", None);
                    if !confirm(start, "annuler").await {
                        return;
                    }
                    glib::timeout_future(Duration::from_millis(1500)).await;
                }
                "sante" => {
                    let Some(d) = dns.as_ref() else { return };
                    let _ = WidgetExt::activate_action(d, "dns.sante", None);
                    let summary = until(LIMIT, || {
                        let s = d.trial_health()?.trial_summary();
                        (!s.is_empty() && !s.ends_with('…')).then_some(s)
                    })
                    .await;
                    eprintln!(
                        "essai dns santé en {:.3} s : {}",
                        start.elapsed().as_secs_f64(),
                        summary.unwrap_or_default()
                    );
                }
                "corriger" => {
                    let Some(health) = dns.as_ref().and_then(crate::dns::DnsWindow::trial_health)
                    else {
                        return;
                    };
                    eprintln!(
                        "essai dns corriger : {} choisie(s)",
                        health.trial_select(arg(1))
                    );
                    if !health.trial_fix() || !confirm(start, "corriger").await {
                        return;
                    }
                    let before = health.trial_summary();
                    let after = until(LIMIT, || {
                        let s = health.trial_summary();
                        (s != before && !s.is_empty() && !s.ends_with('…')).then_some(s)
                    })
                    .await;
                    eprintln!(
                        "essai dns santé relue en {:.3} s : {}",
                        start.elapsed().as_secs_f64(),
                        after.unwrap_or_default()
                    );
                }
                "sante-lignes" => {
                    let Some(health) = dns.as_ref().and_then(crate::dns::DnsWindow::trial_health)
                    else {
                        return;
                    };
                    let text = std::iter::once(health.trial_summary())
                        .chain(health.trial_lines())
                        .collect::<Vec<_>>()
                        .join("\n");
                    match std::fs::write(arg(1), text + "\n") {
                        Ok(()) => eprintln!("essai dns santé écrite : {}", arg(1)),
                        Err(e) => eprintln!("essai dns santé : {e}"),
                    }
                }
                "capture" => {
                    let front = dns
                        .as_ref()
                        .and_then(crate::dns::DnsWindow::trial_health)
                        .map(|h| h.upcast::<gtk::Window>())
                        .filter(|_| arg(2) == "sante")
                        .or_else(|| dns.as_ref().map(|d| d.clone().upcast::<gtk::Window>()));
                    if let Some(front) = front {
                        match capture(&front, std::path::Path::new(arg(1))) {
                            Ok(()) => eprintln!("capture {}", arg(1)),
                            Err(e) => eprintln!("capture {}: {e}", arg(1)),
                        }
                    }
                }
                "pause" => {
                    glib::timeout_future(Duration::from_millis(arg(1).parse().unwrap_or(1000)))
                        .await;
                }
                other => eprintln!("essai dns : étape inconnue {other}"),
            }
        }
        eprintln!("essai dns : fin");
        if std::env::var_os("ANNUAIRE_ESSAI_QUITTER").is_some() {
            if let Some(window) = weak.upgrade() {
                window.close();
            }
        }
    });
}

/// Waits for the GPO window read again after a write (or an action), then prints its tree.
async fn gpo_settled(gpo: &crate::gpo::GpoWindow, start: std::time::Instant, what: &str) {
    glib::timeout_future(Duration::from_millis(300)).await;
    let ready = until(LIMIT, || {
        (gpo.trial_ready() && find::<crate::writes::PreviewDialog>().is_none()).then_some(())
    })
    .await;
    eprintln!(
        "essai gpo {what} : relu {} en {:.3} s, choisi {:?}",
        ready.is_some(),
        start.elapsed().as_secs_f64(),
        gpo.trial_find("=")
    );
}

/// Waits for the editor read again (tree shown, no preview), then prints its page.
async fn editor_settled(
    editor: &crate::gpo_editor::GpoEditor,
    start: std::time::Instant,
    what: &str,
) {
    glib::timeout_future(Duration::from_millis(300)).await;
    let ready = until(LIMIT, || {
        (editor.trial_ready()
            && editor.trial_times().1.is_some()
            && find::<crate::writes::PreviewDialog>().is_none())
        .then_some(())
    })
    .await;
    eprintln!(
        "essai éditeur {what} : relu {} en {:.3} s",
        ready.is_some(),
        start.elapsed().as_secs_f64()
    );
    if let Some(page) = find::<crate::templates::TemplatesPage>() {
        for line in page.trial_rows().iter().take(40) {
            eprintln!("essai éditeur ligne : {line}");
        }
    }
}

/// Steps of the security settings (R4.9c), in the dialog of the « Group Policy » window or in
/// the editor (the page shown): `securite|NODE` (dialog opened), `se-page|KEY` (page of the
/// dialog: `mot-de-passe`, `verrouillage`, `droits`, `groupes`), `se-reglage|KEY|VALUE` (empty:
/// not defined), `se-droit|NAME|ENTRY|DEFINED` (DEFINED `0`: not defined),
/// `se-groupe|ENTRY|MEMBER`, `se-retirer-groupe|ENTRY`, `se-lignes`, `se-enregistrer`.
async fn security_step(g: &crate::gpo::GpoWindow, p: &[&str], start: std::time::Instant) -> bool {
    use crate::gpo_security::{
        AccountsPage, GroupsPage, PrincipalsDialog, RightsPage, SecurityDialog,
    };
    let arg = |i: usize| p.get(i).copied().unwrap_or_default();
    match arg(0) {
        "securite" => {
            let Some(key) = g.trial_find(arg(1)) else {
                eprintln!("essai sécurité : nœud {} introuvable", arg(1));
                return false;
            };
            g.trial_choose(&key);
            g.trial_action("securite");
            let ready = until(LIMIT, || {
                find::<SecurityDialog>().filter(SecurityDialog::trial_ready)
            })
            .await;
            eprintln!(
                "essai sécurité ouvert : {} en {:.3} s",
                ready.is_some(),
                start.elapsed().as_secs_f64()
            );
        }
        "se-page" => {
            let Some(d) = find::<SecurityDialog>() else {
                return false;
            };
            d.open(arg(1));
            glib::timeout_future(Duration::from_millis(300)).await;
        }
        "se-reglage" => {
            let Some(page) = until(LIMIT, find_shown::<AccountsPage>).await else {
                return false;
            };
            page.trial_set(arg(1), arg(2).parse().ok());
        }
        "se-droit" => {
            let Some(page) = until(LIMIT, find_shown::<RightsPage>).await else {
                return false;
            };
            page.trial_open(arg(1));
            let Some(d) = until(LIMIT, find::<PrincipalsDialog>).await else {
                return false;
            };
            d.trial((!arg(2).is_empty()).then(|| arg(2)), arg(3) != "0");
        }
        "se-groupe" => {
            let Some(page) = until(LIMIT, find_shown::<GroupsPage>).await else {
                return false;
            };
            let members = arg(2)
                .split(',')
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect();
            page.trial_put(arg(1), members);
        }
        "se-retirer-groupe" => {
            let Some(page) = until(LIMIT, find_shown::<GroupsPage>).await else {
                return false;
            };
            page.trial_remove(arg(1));
        }
        "se-lignes" => {
            for w in gtk::Window::list_toplevels() {
                for widget in crate::sheet::all_under(&w) {
                    if let Some(row) = widget.downcast_ref::<adw::ActionRow>()
                        && row.is_mapped()
                    {
                        use adw::prelude::*;
                        eprintln!(
                            "essai sécurité ligne : {} | {}",
                            row.title(),
                            row.subtitle().unwrap_or_default()
                        );
                    }
                }
            }
        }
        "se-enregistrer" => {
            let Some(d) = find::<SecurityDialog>() else {
                return false;
            };
            d.trial_save();
            if !confirm(start, "sécurité").await {
                return false;
            }
            gpo_settled(g, start, "sécurité").await;
        }
        other => eprintln!("essai sécurité : étape inconnue {other}"),
    }
    true
}

/// The element dialog of preferences shown, as `$d` in `$body`.
macro_rules! with_element_dialog {
    ($d:ident => $body:expr) => {{
        use crate::preferences::{DriveDialog, PrinterDialog, RegistryDialog, ShortcutDialog};
        if let Some($d) = find_shown::<DriveDialog>() {
            Some($body)
        } else if let Some($d) = find_shown::<PrinterDialog>() {
            Some($body)
        } else if let Some($d) = find_shown::<ShortcutDialog>() {
            Some($body)
        } else if let Some($d) = find_shown::<RegistryDialog>() {
            Some($body)
        } else {
            None
        }
    }};
}

/// The page of preferences of the node chosen in the editor.
fn preference_page(
    editor: &crate::gpo_editor::GpoEditor,
) -> Option<crate::preferences::PreferencesPage> {
    let key = editor.chosen_node()?.key;
    gtk::Window::list_toplevels().into_iter().find_map(|w| {
        crate::sheet::all_under(&w)
            .into_iter()
            .filter(WidgetExt::is_mapped)
            .filter_map(|w| w.downcast::<crate::preferences::PreferencesPage>().ok())
            .find(|p| p.trial_key() == key)
    })
}

fn preference_rows(editor: &crate::gpo_editor::GpoEditor) {
    if let Some(page) = preference_page(editor) {
        for line in page.trial_rows() {
            eprintln!("essai préférences ligne : {line}");
        }
    }
}

/// Steps of the preferences (R4.9): `pr-noeud|KEY` (`pref:utilisateur:Drives`…),
/// `pr-geste|GESTURE|ROW` (`ajouter`, `modifier`, `supprimer`, `monter`, `descendre`),
/// `pr-champ|FIELD|VALUE` (in the element dialog shown), `pr-cible|TAG|TEXT` (filter
/// `FilterGroup`… searched, first result), `pr-continuer`, `pr-lignes`.
async fn preferences_step(editor: &crate::gpo_editor::GpoEditor, p: &[&str]) -> bool {
    let arg = |i: usize| p.get(i).copied().unwrap_or_default();
    match arg(0) {
        "pr-noeud" => {
            editor.choose(arg(1));
            let page = until(LIMIT, || preference_page(editor)).await;
            eprintln!("essai préférences page {} : {}", arg(1), page.is_some());
        }
        "pr-geste" => {
            let Some(page) = preference_page(editor) else {
                return false;
            };
            page.trial_gesture(arg(1), arg(2).parse().unwrap_or(0));
            glib::timeout_future(Duration::from_millis(300)).await;
        }
        "pr-champ" => {
            let done = with_element_dialog!(d => d.trial_set(arg(1), arg(2)));
            if done != Some(true) {
                eprintln!("essai préférences : champ {} non posé", arg(1));
                return false;
            }
        }
        "pr-cible" => {
            if with_element_dialog!(d => d.trial_target(arg(1))).is_none() {
                return false;
            }
            let Some(d) = until(LIMIT, find_shown::<crate::preferences::TargetDialog>).await else {
                return false;
            };
            if !d.trial_choose(arg(2)).await {
                eprintln!("essai préférences : cible {} non choisie", arg(2));
                return false;
            }
            glib::timeout_future(Duration::from_millis(300)).await;
        }
        "pr-continuer" => {
            let message = with_element_dialog!(d => {
                let message = d.trial_message();
                d.trial_continue();
                message
            });
            match message {
                None => return false,
                Some(m) if !m.is_empty() => eprintln!("essai préférences refus : {m}"),
                Some(_) => {}
            }
            glib::timeout_future(Duration::from_millis(300)).await;
            eprintln!("essai éditeur brouillon : {}", editor.trial_draft());
        }
        _ => {}
    }
    preference_rows(editor);
    true
}

/// Steps of the content editor (R4.9): `editeur|NODE` (opened on the GPO of the node, tree
/// printed), `ed-noeud|KEY`, `ed-chercher|TEXT`, `ed-strategie|IDENT|STATE` (state: `activee`,
/// `desactivee`, `non-configuree`), `ed-brut|ACTION|KEY|NAME|TYPE|DATA|HEX` (raw entry of the
/// part shown; ACTION `poser`, `supprimer`, `supprimer_tout`; TYPE a number), `ed-retirer|ROW`,
/// `ed-enregistrer`, `ed-annuler`, `ed-abandonner`, `ed-fermer`.
#[allow(clippy::too_many_lines)]
async fn editor_step(g: &crate::gpo::GpoWindow, p: &[&str], start: std::time::Instant) -> bool {
    use annuaire_core::policies::State;
    let arg = |i: usize| p.get(i).copied().unwrap_or_default();
    if arg(0) == "editeur" {
        let Some(key) = g.trial_find(arg(1)) else {
            eprintln!("essai éditeur : nœud {} introuvable", arg(1));
            return false;
        };
        g.trial_choose(&key);
        g.trial_action("modifier");
        let Some(editor) = until(LIMIT, || g.editor()).await else {
            return false;
        };
        let read = until(LIMIT, || editor.trial_ready().then_some(())).await;
        eprintln!(
            "essai éditeur ouvert : {} en {:.3} s",
            read.is_some(),
            start.elapsed().as_secs_f64()
        );
        let page = until(LIMIT, || {
            find::<crate::templates::TemplatesPage>()
                .filter(|p| !p.trial_rows().is_empty() || p.trial_times().1.is_some())
        })
        .await;
        let shown = until(LIMIT, || {
            let rows = page.as_ref()?.trial_rows();
            (!rows.is_empty()).then_some(rows)
        })
        .await;
        eprintln!(
            "essai éditeur modèles : {} lignes en {:.3} s",
            shown.as_ref().map_or(0, Vec::len),
            start.elapsed().as_secs_f64()
        );
        for line in editor.trial_tree() {
            eprintln!("essai éditeur arbre : {line}");
        }
        return true;
    }
    let Some(editor) = g.editor() else {
        eprintln!("essai éditeur : pas d'éditeur");
        return false;
    };
    let page = || find::<crate::templates::TemplatesPage>();
    match arg(0) {
        "ed-noeud" => {
            editor.choose(arg(1));
            glib::timeout_future(Duration::from_millis(200)).await;
            if let Some(page) = page() {
                let (asked, shown) = page.trial_times();
                eprintln!(
                    "essai éditeur nœud {} : {:?}",
                    arg(1),
                    asked
                        .zip(shown)
                        .map(|(a, s)| s.duration_since(a).as_secs_f64())
                );
                for line in page.trial_rows().iter().take(40) {
                    eprintln!("essai éditeur ligne : {line}");
                }
            }
        }
        "ed-chercher" => {
            let Some(page) = page() else { return false };
            page.trial_search(arg(1));
            let (asked, shown) = page.trial_times();
            eprintln!(
                "essai éditeur recherche {} : {:?} s",
                arg(1),
                asked
                    .zip(shown)
                    .map(|(a, s)| s.duration_since(a).as_secs_f64())
            );
            for line in page.trial_rows().iter().take(20) {
                eprintln!("essai éditeur ligne : {line}");
            }
        }
        "ed-strategie" => {
            let Some(page) = page() else { return false };
            if !page.trial_open(arg(1)) {
                eprintln!("essai éditeur : stratégie {} absente de la liste", arg(1));
                return false;
            }
            let Some(d) = until(LIMIT, find::<crate::templates::PolicyDialog>).await else {
                return false;
            };
            let state = match arg(2) {
                "activee" => State::Enabled,
                "desactivee" => State::Disabled,
                _ => State::NotConfigured,
            };
            d.trial_apply(state);
            glib::timeout_future(Duration::from_millis(100)).await;
            for line in page.trial_rows().iter().take(40) {
                eprintln!("essai éditeur ligne : {line}");
            }
        }
        "ed-brut" => {
            let Some(page) = page() else { return false };
            page.trial_input();
            let Some(d) = until(LIMIT, find::<crate::templates::RawDialog>).await else {
                return false;
            };
            let action = match arg(1) {
                "supprimer" => crate::template_views::RawAction::Delete,
                "supprimer_tout" => crate::template_views::RawAction::DeleteAll,
                _ => crate::template_views::RawAction::Set,
            };
            d.trial_fill(
                &crate::template_views::RawForm {
                    action,
                    key: arg(2).into(),
                    name: arg(3).into(),
                    rtype: arg(4).parse().unwrap_or(1),
                    data: arg(5).replace("\\n", "\n"),
                    decimal: arg(6) != "1",
                },
                true,
            );
            glib::timeout_future(Duration::from_millis(100)).await;
            for line in page.trial_rows() {
                eprintln!("essai éditeur ligne : {line}");
            }
        }
        "ed-retirer" => {
            let Some(page) = page() else { return false };
            page.trial_remove(arg(1).parse().unwrap_or(0));
            glib::timeout_future(Duration::from_millis(100)).await;
            for line in page.trial_rows() {
                eprintln!("essai éditeur ligne : {line}");
            }
        }
        "ed-enregistrer" => {
            editor.trial_save();
            if !confirm(start, "enregistrer").await {
                return false;
            }
            editor_settled(&editor, start, "enregistrer").await;
        }
        "ed-annuler" => {
            let _ = WidgetExt::activate_action(&editor, "editeur.annuler", None);
            if !confirm(start, "annuler").await {
                return false;
            }
            editor_settled(&editor, start, "annuler").await;
        }
        "ed-abandonner" => {
            let _ = WidgetExt::activate_action(&editor, "editeur.abandonner", None);
        }
        "ed-fermer" => editor.close(),
        step if step.starts_with("pr-") => return preferences_step(&editor, p).await,
        other => eprintln!("essai éditeur : étape inconnue {other}"),
    }
    true
}

/// Steps in the « Group Policy » window (R4.8): `domaine|DOMAIN`, `gpo` (opened, tree
/// printed), `arbre`, `detail|NODE`, `creer|NAME`, `lier|NODE|GPO|enforced`, `action|NODE|NAME`
/// (an action that goes to the preview, or a toggle), `filtrage|NODE|SID|NAME|REMOVED`,
/// `sauvegarder|NODE|FOLDER`, `restaurer|FOLDER|GUID|COPY`, `annuler`, and in the « Password
/// Policies » window: `pso`, `pso-creer|NAME|PRECEDENCE|LENGTH`, `pso-modifier|NAME|LENGTH`,
/// `pso-supprimer|NAME`. NODE: as `GpoWindow::trial_find`.
fn gpo_trial(window: &crate::window::Window, steps: Vec<String>) {
    let weak = window.downgrade();
    glib::spawn_future_local(async move {
        let mut gpo: Option<crate::gpo::GpoWindow> = None;
        let mut pso: Option<crate::pso::PsoWindow> = None;
        for step in steps {
            let Some(window) = weak.upgrade() else { return };
            let p: Vec<&str> = step.split('|').collect();
            let arg = |i: usize| p.get(i).copied().unwrap_or_default();
            let start = std::time::Instant::now();
            let choose = |g: &crate::gpo::GpoWindow, spec: &str| -> bool {
                let Some(key) = g.trial_find(spec) else {
                    eprintln!("essai gpo : nœud {spec} introuvable");
                    return false;
                };
                g.trial_choose(&key)
            };
            match arg(0) {
                "domaine" => {
                    let _ = WidgetExt::activate_action(
                        &window,
                        "win.ouvrir-profil",
                        Some(&arg(1).to_variant()),
                    );
                    if until(LIMIT, || window.source()).await.is_none() {
                        eprintln!("essai gpo : domaine non ouvert");
                        return;
                    }
                }
                "gpo" => {
                    let _ = WidgetExt::activate_action(&window, "win.gpo", None);
                    gpo = until(LIMIT, || window.imp_gpo()).await;
                    let Some(g) = gpo.as_ref() else { return };
                    let ready = until(LIMIT, || g.trial_ready().then_some(())).await;
                    glib::timeout_future(Duration::from_millis(200)).await;
                    eprintln!(
                        "essai gpo fenêtre : {} en {:.3} s, arbre dessiné en {:?} s",
                        ready.is_some(),
                        start.elapsed().as_secs_f64(),
                        g.trial_measure()
                    );
                    for line in g.trial_tree() {
                        eprintln!("essai gpo arbre : {line}");
                    }
                }
                "arbre" => {
                    let Some(g) = gpo.as_ref() else { return };
                    for line in g.trial_tree() {
                        eprintln!("essai gpo arbre : {line}");
                    }
                }
                "detail" => {
                    let Some(g) = gpo.as_ref() else { return };
                    if !choose(g, arg(1)) {
                        return;
                    }
                    glib::timeout_future(Duration::from_millis(100)).await;
                    for line in g.trial_detail() {
                        eprintln!("essai gpo détail : {line}");
                    }
                }
                "creer" => {
                    let Some(g) = gpo.as_ref() else { return };
                    g.trial_action("creer");
                    let Some(d) = until(LIMIT, find::<crate::gpo_dialogs::NameDialog>).await else {
                        return;
                    };
                    d.trial(arg(1));
                    if !confirm(start, "creer").await {
                        return;
                    }
                    gpo_settled(g, start, "creer").await;
                }
                "lier" => {
                    let Some(g) = gpo.as_ref() else { return };
                    if !choose(g, arg(1)) {
                        return;
                    }
                    g.trial_action("lier");
                    let Some(d) = until(LIMIT, find::<crate::gpo_dialogs::LinkDialog>).await else {
                        return;
                    };
                    if !d.trial(arg(2), arg(3) == "1") {
                        eprintln!("essai gpo : GPO {} introuvable", arg(2));
                        return;
                    }
                    if !confirm(start, "lier").await {
                        return;
                    }
                    gpo_settled(g, start, "lier").await;
                }
                "action" => {
                    let Some(g) = gpo.as_ref() else { return };
                    if !choose(g, arg(1)) {
                        return;
                    }
                    g.trial_action(arg(2));
                    if !confirm(start, arg(2)).await {
                        return;
                    }
                    gpo_settled(g, start, arg(2)).await;
                }
                "filtrage" => {
                    let Some(g) = gpo.as_ref() else { return };
                    if !choose(g, arg(1)) {
                        return;
                    }
                    g.trial_action("filtrage");
                    let Some(d) = until(LIMIT, find::<crate::gpo_dialogs::FilteringDialog>).await
                    else {
                        return;
                    };
                    let add = arg(2)
                        .parse::<annuaire_codecs::Sid>()
                        .ok()
                        .map(|s| (s, arg(3)));
                    let removed: Vec<&str> = arg(4).split(',').filter(|x| !x.is_empty()).collect();
                    d.trial(add, &removed);
                    if !confirm(start, "filtrage").await {
                        return;
                    }
                    gpo_settled(g, start, "filtrage").await;
                }
                "sauvegarder" => {
                    let Some(g) = gpo.as_ref() else { return };
                    if !choose(g, arg(1)) {
                        return;
                    }
                    g.trial_action("sauvegarder");
                    let Some(d) = until(LIMIT, find::<crate::gpo_dialogs::BackupDialog>).await
                    else {
                        return;
                    };
                    d.trial(arg(2));
                    let gone = until(LIMIT, || {
                        find::<crate::gpo_dialogs::BackupDialog>()
                            .is_none()
                            .then_some(())
                    })
                    .await;
                    eprintln!(
                        "essai gpo sauvegarde : {} en {:.3} s",
                        gone.is_some(),
                        start.elapsed().as_secs_f64()
                    );
                }
                "restaurer" => {
                    let Some(g) = gpo.as_ref() else { return };
                    g.trial_action("restaurer");
                    let Some(d) = until(LIMIT, find::<crate::gpo_dialogs::RestoreDialog>).await
                    else {
                        return;
                    };
                    let copy = (!arg(3).is_empty()).then(|| arg(3));
                    if !d.trial(arg(1), arg(2), copy) {
                        eprintln!("essai gpo : archive {} introuvable", arg(2));
                        return;
                    }
                    if !confirm(start, "restaurer").await {
                        return;
                    }
                    gpo_settled(g, start, "restaurer").await;
                }
                "annuler" => {
                    let Some(g) = gpo.as_ref() else { return };
                    g.trial_action("annuler-derniere");
                    if !confirm(start, "annuler").await {
                        return;
                    }
                    gpo_settled(g, start, "annuler").await;
                }
                "pso" => {
                    let _ = WidgetExt::activate_action(&window, "win.pso", None);
                    pso = until(LIMIT, || window.imp_pso()).await;
                    let Some(w) = pso.as_ref() else { return };
                    let ready = until(LIMIT, || w.trial_ready().then_some(())).await;
                    eprintln!(
                        "essai pso fenêtre : {} en {:.3} s",
                        ready.is_some(),
                        start.elapsed().as_secs_f64()
                    );
                    for line in w.trial_rows() {
                        eprintln!("essai pso ligne : {}", line.replace('\n', " / "));
                    }
                }
                "pso-creer" | "pso-modifier" => {
                    let Some(w) = pso.as_ref() else { return };
                    let creating = arg(0) == "pso-creer";
                    w.trial_open((!creating).then(|| arg(1)));
                    let Some(d) = until(LIMIT, find::<crate::pso::PsoDialog>).await else {
                        return;
                    };
                    let number = |i: usize| arg(i).parse::<i64>().ok();
                    if creating {
                        d.trial(Some(arg(1)), number(2), number(3));
                    } else {
                        d.trial(None, None, number(2));
                    }
                    if !confirm(start, arg(0)).await {
                        eprintln!("essai pso problèmes : {}", d.trial_problems());
                        return;
                    }
                    glib::timeout_future(Duration::from_millis(300)).await;
                    let _ = until(LIMIT, || w.trial_ready().then_some(())).await;
                    for line in w.trial_rows() {
                        eprintln!("essai pso ligne : {}", line.replace('\n', " / "));
                    }
                }
                "pso-supprimer" => {
                    let Some(w) = pso.as_ref() else { return };
                    w.trial_delete(arg(1));
                    if !confirm(start, "pso-supprimer").await {
                        return;
                    }
                    glib::timeout_future(Duration::from_millis(300)).await;
                    let _ = until(LIMIT, || w.trial_ready().then_some(())).await;
                    for line in w.trial_rows() {
                        eprintln!("essai pso ligne : {}", line.replace('\n', " / "));
                    }
                }
                "pause" => {
                    let ms = arg(1).parse().unwrap_or(1000);
                    glib::timeout_future(Duration::from_millis(ms)).await;
                }
                step if step.starts_with("se") => {
                    let Some(g) = gpo.as_ref() else { return };
                    if !security_step(g, &p, start).await {
                        return;
                    }
                }
                step if step.starts_with("ed") || step.starts_with("pr-") => {
                    let Some(g) = gpo.as_ref() else { return };
                    if !editor_step(g, &p, start).await {
                        return;
                    }
                }
                other => eprintln!("essai gpo : étape inconnue {other}"),
            }
        }
        eprintln!("essai gpo fin");
    });
}
