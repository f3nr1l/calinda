// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The self-relative security descriptor MS-GKDI seeds a key against (MS-DTYP). For a SID
//! protection descriptor, the DC computes the seed keys over exactly these bytes, so the order
//! of the dynamic part matters: SACL, DACL, owner, group (MS-DTYP appendix A footnote). The
//! target descriptor has no SACL, a DACL of one ACE per target then the caller (World), and
//! SYSTEM as owner and group.

use super::DpapiError;

/// A SID string (`S-1-5-21-…`) to its binary form: revision, sub-authority count, the 6-byte
/// big-endian authority, then each sub-authority as little-endian 4 bytes.
fn sid_to_bytes(sid: &str) -> Result<Vec<u8>, DpapiError> {
    let bad = || DpapiError::Malformed(format!("invalid SID '{sid}'"));
    let mut parts = sid.split('-');
    if parts.next() != Some("S") {
        return Err(bad());
    }
    let revision: u8 = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let authority: u64 = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let subs: Vec<u32> = parts
        .map(|s| s.parse::<u32>().map_err(|_| bad()))
        .collect::<Result<_, _>>()?;
    if subs.is_empty() || subs.len() > 15 {
        return Err(bad());
    }
    let mut data = authority.to_be_bytes().to_vec(); // 8 bytes; the top two become revision/count
    if let Some(first) = data.first_mut() {
        *first = revision;
    }
    if let Some(second) = data.get_mut(1) {
        *second = u8::try_from(subs.len()).unwrap_or(0);
    }
    for sub in subs {
        data.extend_from_slice(&sub.to_le_bytes());
    }
    Ok(data)
}

/// An `ACCESS_ALLOWED_ACE` granting `access_mask` to `sid`.
fn ace_to_bytes(sid: &str, access_mask: u32) -> Result<Vec<u8>, DpapiError> {
    let b_sid = sid_to_bytes(sid)?;
    let size = u16::try_from(8 + b_sid.len()).unwrap_or(0);
    let mut ace = vec![0u8, 0]; // AceType ACCESS_ALLOWED, AceFlags
    ace.extend_from_slice(&size.to_le_bytes());
    ace.extend_from_slice(&access_mask.to_le_bytes());
    ace.extend_from_slice(&b_sid);
    Ok(ace)
}

/// An ACL (revision 2) wrapping the ACEs.
fn acl_to_bytes(aces: &[Vec<u8>]) -> Vec<u8> {
    let ace_data: Vec<u8> = aces.concat();
    let size = u16::try_from(8 + ace_data.len()).unwrap_or(0);
    let count = u16::try_from(aces.len()).unwrap_or(0);
    let mut acl = vec![0x02u8, 0]; // AclRevision, Sbz1
    acl.extend_from_slice(&size.to_le_bytes());
    acl.extend_from_slice(&count.to_le_bytes());
    acl.extend_from_slice(&[0, 0]); // Sbz2
    acl.extend_from_slice(&ace_data);
    acl
}

/// The target security descriptor for a SID protection descriptor: owner and group SYSTEM, a
/// DACL granting the target SID 0x3 and World (the caller) 0x2, no SACL.
pub fn target_sd_for_sid(sid: &str) -> Result<Vec<u8>, DpapiError> {
    let dacl = acl_to_bytes(&[ace_to_bytes(sid, 3)?, ace_to_bytes("S-1-1-0", 2)?]);
    let owner = sid_to_bytes("S-1-5-18")?;
    let group = sid_to_bytes("S-1-5-18")?;

    // Control: self-relative, DACL present.
    let control: u16 = (0b1000_0000 << 8) | 0b0000_0100;
    let header_len = 20u32;
    let dacl_offset = header_len;
    let owner_offset = dacl_offset + u32::try_from(dacl.len()).unwrap_or(0);
    let group_offset = owner_offset + u32::try_from(owner.len()).unwrap_or(0);

    let mut sd = vec![0x01u8, 0]; // Revision, Sbz1
    sd.extend_from_slice(&control.to_le_bytes());
    sd.extend_from_slice(&owner_offset.to_le_bytes());
    sd.extend_from_slice(&group_offset.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // no SACL
    sd.extend_from_slice(&dacl_offset.to_le_bytes());
    sd.extend_from_slice(&dacl);
    sd.extend_from_slice(&owner);
    sd.extend_from_slice(&group);
    Ok(sd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sid_encodes_like_ms_dtyp() {
        // S-1-5-18 (Local System): revision 1, one sub-authority, authority 5.
        assert_eq!(
            sid_to_bytes("S-1-5-18").unwrap(),
            [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
        );
    }
}
