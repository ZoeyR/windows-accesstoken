use std::convert::TryInto;

use winapi::um::winnt::{
    TokenElevationType, TokenGroups, TokenLinkedToken, HANDLE, SID_AND_ATTRIBUTES,
    TOKEN_INFORMATION_CLASS,
};

use crate::{security::GroupSidAttributes, security::SecurityIdentifier, AccessToken};

pub unsafe trait TokenInformation {
    const LEVEL: TOKEN_INFORMATION_CLASS;
    type Output;

    unsafe fn from_buf(buf: &[u8]) -> Option<Self::Output>;
}

#[derive(PartialEq, Eq)]
pub enum TokenElevation {
    Unknown = 0,
    Default = 1,
    Full = 2,
    Limited = 3,
}

unsafe impl TokenInformation for TokenElevation {
    const LEVEL: TOKEN_INFORMATION_CLASS = TokenElevationType;
    type Output = Self;

    unsafe fn from_buf(buf: &[u8]) -> Option<Self::Output> {
        Some(match u32::from_ne_bytes(buf.try_into().unwrap()) {
            1 => TokenElevation::Default,
            2 => TokenElevation::Full,
            3 => TokenElevation::Limited,
            _ => TokenElevation::Unknown,
        })
    }
}

pub struct LinkedToken;

unsafe impl TokenInformation for LinkedToken {
    const LEVEL: TOKEN_INFORMATION_CLASS = TokenLinkedToken;
    type Output = AccessToken;

    unsafe fn from_buf(buf: &[u8]) -> Option<Self::Output> {
        let handle = buf.as_ptr() as *const _ as *const HANDLE;
        if handle.is_null() {
            return None;
        }

        Some(AccessToken::from_raw_handle(*handle))
    }
}

pub struct Groups;

unsafe impl TokenInformation for Groups {
    const LEVEL: TOKEN_INFORMATION_CLASS = TokenGroups;

    type Output = Vec<(SecurityIdentifier, GroupSidAttributes)>;

    unsafe fn from_buf(buf: &[u8]) -> Option<Self::Output> {
        let count = u32::from_ne_bytes(buf[0..4].try_into().unwrap());

        let arr_start = buf[4..].as_ptr() as *const SID_AND_ATTRIBUTES;
        let mut output = Vec::new();
        for i in 0..count {
            let sid_attr = *arr_start.offset(i as isize);
            output.push((
                SecurityIdentifier::from_raw(sid_attr.Sid),
                GroupSidAttributes::from_bits_unchecked(sid_attr.Attributes),
            ));
        }

        Some(output)
    }
}
