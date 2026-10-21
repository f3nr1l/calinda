// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Trial of `kerberos::obtain_ticket` (R4.2) against a KDC, as `kinit`: the password is read on
//! the standard input, never shown; the ticket goes to the cache of `KRB5CCNAME`.
//!
//! ```text
//! printf %s "$PASSWORD" | KRB5CCNAME=FILE:… cargo run --example ticket -- administrator LAB.TEST
//! ```

use std::io::Read;

use annuaire_core::kerberos;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [account, realm] = args.as_slice() else {
        return Err("usage: ticket ACCOUNT REALM < password".into());
    };
    let principal =
        kerberos::principal_from_input(account, Some(realm)).map_err(|e| format!("{e:?}"))?;
    let mut password = Vec::new();
    std::io::stdin().read_to_end(&mut password)?;
    while password.last().is_some_and(|b| *b == b'\n') {
        password.pop();
    }
    match kerberos::obtain_ticket(&principal, &mut password) {
        Ok(ticket) => println!("ticket {} (end: {:?})", ticket.principal, ticket.end),
        Err(e) => println!("refused: {:?} ({})", e.kind, e.detail),
    }
    println!(
        "cache read again: {:?}",
        kerberos::read_ticket(None).map(|t| t.principal)
    );
    Ok(())
}
