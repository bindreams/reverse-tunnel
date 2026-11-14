//! Windows security descriptors from SDDL strings: one string says an object's whole owner and DACL, whether it is
//! made with it or an existing one is given it.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows::core::PCWSTR;
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, FILE_ALL_ACCESS};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
};

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

pub(crate) fn wide(path: &Path) -> Vec<u16> {
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

/// An allow or deny ACE of a DACL.
pub struct Ace {
    pub allows: bool,
    /// Applies to what the object contains, not to the object.
    pub inherit_only: bool,
    pub mask: u32,
    pub sid: Sid,
}

/// The plain allow ACEs and every kind of deny ACE (plain, callback, object, callback object) of `path`'s DACL,
/// inherited ones included. Other allows (conditional, object) are left out: nothing may rely on them. A path with no
/// DACL gives everyone full access, so it has one ACE: Everyone's.
pub fn aces_of(path: &Path) -> io::Result<Vec<Ace>> {
    let (mut dacl, mut descriptor) = (null_mut(), null_mut());
    // SAFETY: the path is NUL-terminated, and the out pointers are live.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(os_error(code));
    }
    let _descriptor = Local(descriptor);
    if dacl.is_null() {
        return Ok(vec![Ace {
            allows: true,
            inherit_only: false,
            mask: FILE_ALL_ACCESS,
            sid: Sid::parse("S-1-1-0")?,
        }]);
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` points into the live descriptor, and `info` is the size that the call is told.
    let read = unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut aces = Vec::new();
    for at in 0..info.AceCount {
        let mut ace = null_mut();
        // SAFETY: `at` is below the ACL's count, and the out pointer is live.
        if unsafe { GetAce(dacl, at, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `ace` points into the live descriptor at an ACE, which starts with its header.
        let header = unsafe { *ace.cast::<ACE_HEADER>() };
        let kind = u32::from(header.AceType);
        let allows = kind == ACCESS_ALLOWED_ACE_TYPE;
        let object = matches!(
            kind,
            ACCESS_DENIED_OBJECT_ACE_TYPE | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
        );
        if !allows && kind != ACCESS_DENIED_ACE_TYPE && kind != ACCESS_DENIED_CALLBACK_ACE_TYPE && !object {
            continue;
        }
        // SAFETY: every one of these ACEs is the header, the mask, then for an object ACE its flags and the GUIDs that
        // they say are present, and then the SID, which is valid for as long as the descriptor is.
        let (mask, sid) = unsafe {
            let base = ace.cast::<u8>();
            let mask = base.add(4).cast::<u32>().read_unaligned();
            let mut sid_at = 8;
            if object {
                let flags = base.add(8).cast::<u32>().read_unaligned();
                sid_at = 12
                    + 16 * usize::from(flags & ACE_OBJECT_TYPE_PRESENT != 0)
                    + 16 * usize::from(flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0);
            }
            (mask, Sid::copy_of(base.add(sid_at).cast()))
        };
        aces.push(Ace {
            allows,
            inherit_only: u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0,
            mask,
            sid,
        });
    }
    Ok(aces)
}

/// The text of the SID that `sid` points to, as `S-1-5-...`.
///
/// # Safety
/// `sid` points to a valid SID.
unsafe fn string_of_sid(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    // SAFETY: the caller's promise.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _text = Local(text.cast());
    // SAFETY: Windows wrote a NUL-terminated string.
    unsafe { PCWSTR(text).to_string() }.map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// A SID, in its binary form.
pub struct Sid(Vec<u32>);

impl Sid {
    /// The SID that `text` (`S-1-5-...`) spells.
    pub fn parse(text: &str) -> io::Result<Sid> {
        let text: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let mut sid = null_mut();
        // SAFETY: `text` is NUL-terminated, and the out pointer is live.
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid = Local(sid);
        // SAFETY: Windows made a valid SID, which `sid` keeps until it drops.
        Ok(unsafe { Sid::copy_of(sid.0) })
    }

    /// A copy of the SID that `sid` points to.
    ///
    /// # Safety
    /// `sid` points to a valid SID.
    pub unsafe fn copy_of(sid: PSID) -> Sid {
        // SAFETY: the caller's promise.
        let len = unsafe { GetLengthSid(sid) } as usize;
        // A SID is a whole number of 32-bit words.
        let mut words = vec![0u32; len.div_ceil(4)];
        // SAFETY: `words` has room for `len` bytes, and the caller's promise says `sid` has that many.
        unsafe { std::ptr::copy_nonoverlapping(sid.cast::<u8>(), words.as_mut_ptr().cast::<u8>(), len) };
        Sid(words)
    }

    pub fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    /// The SID as `S-1-5-...`.
    pub fn text(&self) -> io::Result<String> {
        // SAFETY: `self` is a valid SID.
        unsafe { string_of_sid(self.as_psid()) }
    }

    /// Whether `other` is this SID; never for null.
    ///
    /// # Safety
    /// `other` is null or points to a valid SID.
    pub unsafe fn is(&self, other: PSID) -> bool {
        // SAFETY: both are valid SIDs, as the caller promises of `other`.
        !other.is_null() && unsafe { EqualSid(self.as_psid(), other) } != 0
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Sid) -> bool {
        // SAFETY: `other` is a valid SID that it owns.
        unsafe { self.is(other.as_psid()) }
    }
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;
