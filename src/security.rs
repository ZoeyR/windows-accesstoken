use bitflags::bitflags;
use std::ptr;
use winapi::{
    ctypes::c_void,
    um::{
        errhandlingapi::GetLastError, securitybaseapi::CreateWellKnownSid,
        winnt::SID_MAX_SUB_AUTHORITIES,
    },
};

#[derive(PartialEq, Eq)]
pub struct SecurityIdentifier {
    revision: u8,
    identifier: IdentifierAuthority,
    sub_authority: Vec<u32>,
}

#[derive(PartialEq, Eq)]
pub struct IdentifierAuthority {
    value: [u8; 6],
}

pub enum WellKnownSid {
    WinNullSid = 0,
    WinWorldSid = 1,
    WinLocalSid = 2,
    WinCreatorOwnerSid = 3,
    WinCreatorGroupSid = 4,
    WinCreatorOwnerServerSid = 5,
    WinCreatorGroupServerSid = 6,
    WinNtAuthoritySid = 7,
    WinDialupSid = 8,
    WinNetworkSid = 9,
    WinBatchSid = 10,
    WinInteractiveSid = 11,
    WinServiceSid = 12,
    WinAnonymousSid = 13,
    WinProxySid = 14,
    WinEnterpriseControllersSid = 15,
    WinSelfSid = 16,
    WinAuthenticatedUserSid = 17,
    WinRestrictedCodeSid = 18,
    WinTerminalServerSid = 19,
    WinRemoteLogonIdSid = 20,
    WinLogonIdsSid = 21,
    WinLocalSystemSid = 22,
    WinLocalServiceSid = 23,
    WinNetworkServiceSid = 24,
    WinBuiltinDomainSid = 25,
    WinBuiltinAdministratorsSid = 26,
    WinBuiltinUsersSid = 27,
    WinBuiltinGuestsSid = 28,
    WinBuiltinPowerUsersSid = 29,
    WinBuiltinAccountOperatorsSid = 30,
    WinBuiltinSystemOperatorsSid = 31,
    WinBuiltinPrintOperatorsSid = 32,
    WinBuiltinBackupOperatorsSid = 33,
    WinBuiltinReplicatorSid = 34,
    WinBuiltinPreWindows2000CompatibleAccessSid = 35,
    WinBuiltinRemoteDesktopUsersSid = 36,
    WinBuiltinNetworkConfigurationOperatorsSid = 37,
    WinAccountAdministratorSid = 38,
    WinAccountGuestSid = 39,
    WinAccountKrbtgtSid = 40,
    WinAccountDomainAdminsSid = 41,
    WinAccountDomainUsersSid = 42,
    WinAccountDomainGuestsSid = 43,
    WinAccountComputersSid = 44,
    WinAccountControllersSid = 45,
    WinAccountCertAdminsSid = 46,
    WinAccountSchemaAdminsSid = 47,
    WinAccountEnterpriseAdminsSid = 48,
    WinAccountPolicyAdminsSid = 49,
    WinAccountRasAndIasServersSid = 50,
    WinNTLMAuthenticationSid = 51,
    WinDigestAuthenticationSid = 52,
    WinSChannelAuthenticationSid = 53,
    WinThisOrganizationSid = 54,
    WinOtherOrganizationSid = 55,
    WinBuiltinIncomingForestTrustBuildersSid = 56,
    WinBuiltinPerfMonitoringUsersSid = 57,
    WinBuiltinPerfLoggingUsersSid = 58,
    WinBuiltinAuthorizationAccessSid = 59,
    WinBuiltinTerminalServerLicenseServersSid = 60,
    WinBuiltinDCOMUsersSid = 61,
    WinBuiltinIUsersSid = 62,
    WinIUserSid = 63,
    WinBuiltinCryptoOperatorsSid = 64,
    WinUntrustedLabelSid = 65,
    WinLowLabelSid = 66,
    WinMediumLabelSid = 67,
    WinHighLabelSid = 68,
    WinSystemLabelSid = 69,
    WinWriteRestrictedCodeSid = 70,
    WinCreatorOwnerRightsSid = 71,
    WinCacheablePrincipalsGroupSid = 72,
    WinNonCacheablePrincipalsGroupSid = 73,
    WinEnterpriseReadonlyControllersSid = 74,
    WinAccountReadonlyControllersSid = 75,
    WinBuiltinEventLogReadersGroup = 76,
    WinNewEnterpriseReadonlyControllersSid = 77,
    WinBuiltinCertSvcDComAccessGroup = 78,
    WinMediumPlusLabelSid = 79,
    WinLocalLogonSid = 80,
    WinConsoleLogonSid = 81,
    WinThisOrganizationCertificateSid = 82,
    WinApplicationPackageAuthoritySid = 83,
    WinBuiltinAnyPackageSid = 84,
    WinCapabilityInternetClientSid = 85,
    WinCapabilityInternetClientServerSid = 86,
    WinCapabilityPrivateNetworkClientServerSid = 87,
    WinCapabilityPicturesLibrarySid = 88,
    WinCapabilityVideosLibrarySid = 89,
    WinCapabilityMusicLibrarySid = 90,
    WinCapabilityDocumentsLibrarySid = 91,
    WinCapabilitySharedUserCertificatesSid = 92,
    WinCapabilityEnterpriseAuthenticationSid = 93,
    WinCapabilityRemovableStorageSid = 94,
}

bitflags! {
    pub struct GroupSidAttributes : u32
    {
        const SE_GROUP_MANDATORY = 0x00000001;
        const SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002;
        const SE_GROUP_ENABLED = 0x00000004;
        const SE_GROUP_OWNER = 0x00000008;
        const SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        const SE_GROUP_INTEGRITY = 0x00000020;
        const SE_GROUP_INTEGRITY_ENABLED = 0x00000040;
        const SE_GROUP_LOGON_ID = 0xC0000000;
        const SE_GROUP_RESOURCE = 0x20000000;
        const SE_GROUP_VALID_ATTRIBUTES = 0xE000007F;
    }
}

impl SecurityIdentifier {
    pub unsafe fn from_raw(sid: *const c_void) -> Self {
        let sid_start = sid as *const u8;
        let revision = *sid_start;

        let count = *sid_start.offset(1);

        let mut identifier = [0u8; 6];
        for i in 0..6 {
            let value = *sid_start.offset(2 + i);
            identifier[i as usize] = value;
        }

        let authorities_start = sid_start.offset(8) as *const u32;
        let mut sub_authority = Vec::new();
        for i in 0..count {
            sub_authority.push(*authorities_start.offset(i as isize));
        }

        SecurityIdentifier {
            revision,
            identifier: IdentifierAuthority { value: identifier },
            sub_authority,
        }
    }

    pub fn from_known(sid: WellKnownSid) -> Result<Self, std::io::Error> {
        let mut buffer_size = ((SID_MAX_SUB_AUTHORITIES * 4) + 1 + 1 + 6) as u32;
        let mut buffer = vec![0u8; buffer_size as usize];
        unsafe {
            if CreateWellKnownSid(
                sid as u32,
                ptr::null_mut(),
                buffer.as_mut_ptr() as *mut c_void,
                &mut buffer_size,
            ) == 0
            {
                return Err(std::io::Error::from_raw_os_error(GetLastError() as i32));
            }

            Ok(Self::from_raw(buffer.as_ptr() as *mut c_void))
        }
    }
}
