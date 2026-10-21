// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Template callbacks as in the Python application (ADR 0019, section 1). The Blueprint files
//! write `clicked => $_valider();` without `swapped`, and PyGObject calls the method of the
//! template instance with the signal arguments. The callbacks of gtk-rs take their `self` from
//! the first signal argument (the emitter) instead. This scope gives each handler the template
//! instance being built (`Builder::current_object`, kept weakly) and the signal arguments, so
//! the Blueprint files stay those of Python.

use gtk::glib;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

/// A handler: the template instance, the signal arguments (emitter first); the return value of
/// the signal, if it has one.
pub type Handler<T> = fn(&T, &[glib::Value]) -> Option<glib::Value>;

type Erased = Box<dyn Fn(&glib::Object, &[glib::Value]) -> Option<glib::Value>>;

mod imp {
    use std::cell::RefCell;

    use gtk::glib;
    use gtk::prelude::*;
    use gtk::subclass::prelude::*;

    #[derive(Default)]
    pub struct TemplateScope {
        pub handlers: RefCell<Vec<(&'static str, super::Erased)>>,
    }

    impl std::fmt::Debug for TemplateScope {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let names: Vec<&str> = self.handlers.borrow().iter().map(|(n, _)| *n).collect();
            f.debug_struct("TemplateScope")
                .field("handlers", &names)
                .finish()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for TemplateScope {
        const NAME: &'static str = "AnnuaireGabaritScope";
        type Type = super::TemplateScope;
        type Interfaces = (gtk::BuilderScope,);
    }

    impl ObjectImpl for TemplateScope {}

    impl BuilderScopeImpl for TemplateScope {
        fn create_closure(
            &self,
            builder: &gtk::Builder,
            function_name: &str,
            _flags: gtk::BuilderClosureFlags,
            _object: Option<&glib::Object>,
        ) -> Result<glib::Closure, glib::Error> {
            let index = self
                .handlers
                .borrow()
                .iter()
                .position(|(name, _)| *name == function_name)
                .ok_or_else(|| {
                    glib::Error::new(
                        gtk::BuilderError::InvalidFunction,
                        &format!("no template callback named {function_name}"),
                    )
                })?;
            let instance = builder
                .current_object()
                .ok_or_else(|| {
                    glib::Error::new(
                        gtk::BuilderError::InvalidFunction,
                        &format!("{function_name}: no template instance"),
                    )
                })?
                .downgrade();
            let scope = self.obj().downgrade();
            Ok(glib::RustClosure::new_local(move |values| {
                let (Some(instance), Some(scope)) = (instance.upgrade(), scope.upgrade()) else {
                    return None;
                };
                let handlers = scope.imp().handlers.borrow();
                let (_, handler) = handlers.get(index)?;
                handler(&instance, values)
            })
            .as_ref()
            .clone())
        }
    }
}

glib::wrapper! {
    pub struct TemplateScope(ObjectSubclass<imp::TemplateScope>)
        @implements gtk::BuilderScope;
}

impl TemplateScope {
    /// The scope of the template of `T`, with its handlers by name.
    pub fn new<T: IsA<glib::Object>>(handlers: &[(&'static str, Handler<T>)]) -> Self {
        let scope: Self = glib::Object::new();
        let erased = handlers.iter().map(|&(name, handler)| {
            let call: Erased = Box::new(move |object, values| {
                object
                    .downcast_ref::<T>()
                    .and_then(|instance| handler(instance, values))
            });
            (name, call)
        });
        scope.imp().handlers.borrow_mut().extend(erased);
        scope
    }
}
