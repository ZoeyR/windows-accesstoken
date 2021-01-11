#![allow(non_upper_case_globals)]

use bitflags::bitflags;

bitflags! {
    pub struct TokenAccessLevel: u32 {
        const AssignPrimary = 1;
        const Duplicate = 2;
        const Impersonate = 4;
        const Query = 8;
        const QuerySource = 16;
        const AdjustPrivileges = 32;
        const AdjustGroups = 64;
        const AdjustDefault = 128;
        const AdjustSessionId = 256;
        const Read = 0x20000 | TokenAccessLevel::Query.bits;
        const Write = 0x20000
        | TokenAccessLevel::AdjustPrivileges.bits
        | TokenAccessLevel::AdjustGroups.bits
        | TokenAccessLevel::AdjustDefault.bits;
        const AllAccess = 0xF0000
        | TokenAccessLevel::AssignPrimary.bits
        | TokenAccessLevel::Duplicate.bits
        | TokenAccessLevel::Impersonate.bits
        | TokenAccessLevel::Query.bits
        | TokenAccessLevel::QuerySource.bits
        | TokenAccessLevel::AdjustPrivileges.bits
        | TokenAccessLevel::AdjustGroups.bits
        | TokenAccessLevel::AdjustDefault.bits
        | TokenAccessLevel::AdjustSessionId.bits;
        const MaximumAllowed = 0x2000000;
    }
}
