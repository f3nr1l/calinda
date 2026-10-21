// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Link of a flux of pages of the core with the loop of the interface
//! (`annuaire.vue.alimentation`). The flux is produced on the thread of the connection; its
//! notifier only wakes a local task of the GLib loop up, by a channel. The task takes the
//! pages that arrived (`Flux::available`, without waiting) and gives them to the interface by
//! chunks: between two chunks, the loop draws and reads the input. The objects are already
//! decoded by the core; a chunk only makes rows.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use annuaire_core::search::SearchError;
use annuaire_core::source::{Item, Notifier, ObjectFlux};
use futures_util::StreamExt;
use gtk::glib;

/// Items given per pass in the loop.
pub const CHUNK: usize = 250;

/// A flux being fed to the interface; `cancel` stops it (pages not yet given are dropped and
/// the flux frees its cursor). Neither `deliver` nor `finish` are called after `cancel`.
#[derive(Debug)]
pub struct Feed {
    flux: ObjectFlux,
    cancelled: Rc<Cell<bool>>,
    done: Rc<Cell<bool>>,
}

impl Feed {
    /// Starts the search with `open(notifier)`; `deliver` gets each chunk, then `finish` once
    /// (None if the flux ended normally).
    pub fn start(
        open: impl FnOnce(Notifier) -> ObjectFlux,
        deliver: impl Fn(Vec<Item>) + 'static,
        finish: impl FnOnce(Option<Arc<SearchError>>) + 'static,
    ) -> Rc<Self> {
        let (sender, mut wakes) = futures_channel::mpsc::unbounded::<()>();
        let flux = open(Box::new(move || {
            let _ = sender.unbounded_send(());
        }));
        let feed = Rc::new(Self {
            flux: flux.clone(),
            cancelled: Rc::new(Cell::new(false)),
            done: Rc::new(Cell::new(false)),
        });
        let (cancelled, done) = (feed.cancelled.clone(), feed.done.clone());
        glib::spawn_future_local(async move {
            let result = loop {
                let pages = match flux.available() {
                    Ok(pages) => pages,
                    Err(error) => break Some(error),
                };
                for page in pages {
                    let mut items = page.into_iter().peekable();
                    while items.peek().is_some() {
                        if cancelled.get() {
                            return;
                        }
                        deliver(items.by_ref().take(CHUNK).collect());
                        // The rest at the next turn of the loop.
                        glib::timeout_future(Duration::ZERO).await;
                    }
                }
                if cancelled.get() {
                    return;
                }
                if flux.finished() {
                    // Every page was given: what remains is the production error, if any.
                    match flux.available() {
                        Ok(rest) => {
                            for page in rest {
                                deliver(page);
                            }
                            break None;
                        }
                        Err(error) => break Some(error),
                    }
                }
                if wakes.next().await.is_none() {
                    return;
                }
            };
            done.set(true);
            if !cancelled.get() {
                finish(result);
            }
        });
        feed
    }

    pub fn cancel(&self) {
        if !self.done.get() {
            self.cancelled.set(true);
            self.flux.cancel();
        }
    }

    pub fn finished(&self) -> bool {
        self.done.get() || self.cancelled.get()
    }
}
