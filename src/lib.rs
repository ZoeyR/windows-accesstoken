use std::ptr;

use information::TokenInformation;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::HANDLE;
use winapi::um::{
    processthreadsapi::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    securitybaseapi::GetTokenInformation,
};
use winapi::{ctypes::c_void, shared::winerror, um::errhandlingapi::GetLastError};

pub mod information;
mod level;
pub mod security;

pub use level::TokenAccessLevel;

pub struct AccessToken {
    handle: HANDLE,
}

impl AccessToken {
    pub(crate) fn from_raw_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    pub fn open_process(access_level: TokenAccessLevel) -> Result<Self, std::io::Error> {
        let mut handle = ptr::null_mut();
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), access_level.bits(), &mut handle) == 0 {
                let error = std::io::Error::from_raw_os_error(GetLastError() as i32);
                return Err(error);
            }
        }

        Ok(AccessToken { handle })
    }

    pub fn open_thread(
        open_as_self: bool,
        access_level: TokenAccessLevel,
    ) -> Result<Self, std::io::Error> {
        let mut handle = ptr::null_mut();
        unsafe {
            if OpenThreadToken(
                GetCurrentThread(),
                access_level.bits(),
                open_as_self as i32,
                &mut handle,
            ) == 0
            {
                let error = std::io::Error::from_raw_os_error(GetLastError() as i32);
                return Err(error);
            }
        }

        Ok(AccessToken { handle })
    }

    pub fn token_information<T: TokenInformation>(
        &self,
    ) -> Result<Option<T::Output>, std::io::Error> {
        let mut length: u32 = 0;
        unsafe {
            if GetTokenInformation(self.handle, T::LEVEL, ptr::null_mut(), 0, &mut length) != 0 {
                return Ok(None);
            }

            match GetLastError() {
                winerror::ERROR_BAD_LENGTH | winerror::ERROR_INSUFFICIENT_BUFFER => {}
                code => return Err(std::io::Error::from_raw_os_error(code as i32)),
            }

            let mut buffer = vec![0u8; length as usize];
            if GetTokenInformation(
                self.handle,
                T::LEVEL,
                buffer.as_mut_ptr() as *mut c_void,
                length,
                &mut length,
            ) == 0
            {
                let code = GetLastError();
                return Err(std::io::Error::from_raw_os_error(code as i32));
            }

            Ok(T::from_buf(&buffer))
        }
    }
}

impl Drop for AccessToken {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
