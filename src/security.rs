//! Windows security descriptors from SDDL strings: one string says an object's whole owner and DACL, whether it is
//! made with it or an existing one is given it.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

/// A descriptor that names only an owner: Administrators.
pub const OWNED_BY_ADMINISTRATORS: &str = "O:BA";

/// What Windows allocated with `LocalAlloc`, freed when it drops.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a Windows call that allocates with `LocalAlloc`, and is freed only here.
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

fn os_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// A parsed SDDL string.
pub struct Descriptor(Local);

impl Descriptor {
    pub fn parse(sddl: &str) -> io::Result<Descriptor> {
        let text: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = null_mut();
        // SAFETY: `text` is NUL-terminated, and the out pointers are live.
        let parsed = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if parsed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(Local(descriptor)))
    }

    /// Creates the directory `path` with this descriptor, so that it is never there with another. Fails as
    /// `fs::create_dir` does, `AlreadyExists` included.
    pub fn create_dir(&self, path: &Path) -> io::Result<()> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        };
        // SAFETY: the path is NUL-terminated, and the attributes name a descriptor that lives as long as `self`.
        match unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } {
            0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Gives `path` this descriptor's owner, if it has one, and its DACL, if it has one, as a protected DACL; what the
    /// object contains inherits it.
    pub fn apply(&self, path: &Path) -> io::Result<()> {
        let (mut owner, mut dacl, mut present, mut defaulted) = (null_mut(), null_mut(), 0, 0);
        // SAFETY: the descriptor is live, and the out pointers are live; both results point into the descriptor.
        let found = unsafe {
            GetSecurityDescriptorOwner(self.0.0, &mut owner, &mut defaulted) != 0
                && GetSecurityDescriptorDacl(self.0.0, &mut present, &mut dacl, &mut defaulted) != 0
        };
        if !found {
            return Err(io::Error::last_os_error());
        }
        let mut info = 0;
        if !owner.is_null() {
            info |= OWNER_SECURITY_INFORMATION;
        }
        if present != 0 {
            info |= DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        }
        // SAFETY: the path is NUL-terminated, and `owner` and `dacl` are null or point into the live descriptor.
        match unsafe {
            SetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                info,
                owner,
                null_mut(),
                dacl,
                null(),
            )
        } {
            0 => Ok(()),
            code => Err(os_error(code)),
        }
    }
}

/// The SID of `path`'s owner, as `S-1-5-...`.
pub fn owner_of(path: &Path) -> io::Result<String> {
    let (mut owner, mut descriptor) = (null_mut(), null_mut());
    // SAFETY: the path is NUL-terminated, and the out pointers are live.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(os_error(code));
    }
    let _descriptor = Local(descriptor);
    // SAFETY: `owner` points into the descriptor, which is live.
    unsafe { string_of_sid(owner) }
}

/// The text of the SID that `sid` points to, as `S-1-5-...`.
///
/// # Safety
/// `sid` points to a valid SID.
pub(crate) unsafe fn string_of_sid(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    // SAFETY: the caller's promise.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _text = Local(text.cast());
    // SAFETY: Windows wrote a NUL-terminated string.
    let units = unsafe {
        let len = (0..).take_while(|&at| *text.add(at) != 0).count();
        std::slice::from_raw_parts(text, len)
    };
    Ok(String::from_utf16_lossy(units))
}
