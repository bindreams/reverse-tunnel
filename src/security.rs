//! Windows security descriptors from SDDL strings: one string says an object's whole owner and DACL, whether it is
//! made with it or an existing one is given it.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use windows::core::PCWSTR;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Foundation::{GetLastError, STATUS_SUCCESS};
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LsaClose, LsaFreeMemory, LsaOpenPolicy, LsaQueryInformationPolicy,
    POLICY_ACCOUNT_DOMAIN_INFO, POLICY_VIEW_LOCAL_INFORMATION, PolicyAccountDomainInformation,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualDomainSid, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetSidIdentifierAuthority, GetSidSubAuthority,
    GetSidSubAuthorityCount, INHERIT_ONLY_ACE, LookupAccountSidW, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Security::{SidTypeDeletedAccount, SidTypeInvalid, SidTypeUnknown};
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

/// An LSA policy handle, closed when it drops.
struct Policy(LSA_HANDLE);

impl Drop for Policy {
    fn drop(&mut self) {
        // SAFETY: the handle came from `LsaOpenPolicy` and is closed only here.
        unsafe { LsaClose(self.0) };
    }
}

/// What an LSA call allocated (null if it allocated nothing), freed when it drops.
struct LsaMemory(*mut c_void);

impl Drop for LsaMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an LSA call that allocates for the caller, and is freed only here.
            unsafe { LsaFreeMemory(self.0) };
        }
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
        self.set(path, PROTECTED_DACL_SECURITY_INFORMATION)
    }

    /// `apply`, with `protection` the DACL's: protected, or unprotected so that it also gets what the parent gives.
    fn set(&self, path: &Path, protection: u32) -> io::Result<()> {
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
            info |= DACL_SECURITY_INFORMATION | protection;
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

/// Gives `path` the DACL that its parent's inheritable ACEs make, and none of its own: what a file made there has. Any
/// edit of its DACL goes, a protected DACL included. The owner stays.
pub fn inherit_dacl(path: &Path) -> io::Result<()> {
    // An empty DACL, unprotected: Windows adds the inherited ACEs to it.
    Descriptor::parse("D:")?.set(path, UNPROTECTED_DACL_SECURITY_INFORMATION)
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
    /// Files made in the directory inherit it.
    pub object_inherit: bool,
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
            object_inherit: false,
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
        // SAFETY: GetAce gave a pointer to an ACE whose header says it is `AceSize` bytes, inside the live descriptor.
        let bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), usize::from(header.AceSize)) };
        let (mask, sid_at) = layout_of(bytes, object).map_err(|what| {
            let message = format!("{}: ACE {at} is {} bytes, {what}", path.display(), bytes.len());
            io::Error::new(io::ErrorKind::InvalidData, message)
        })?;
        aces.push(Ace {
            allows,
            inherit_only: u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0,
            object_inherit: u32::from(header.AceFlags) & OBJECT_INHERIT_ACE != 0,
            mask,
            // SAFETY: `layout_of` checked that a whole SID lies inside the ACE, which the live descriptor holds.
            sid: unsafe { Sid::copy_of(bytes.as_ptr().add(sid_at).cast_mut().cast()) },
        });
    }
    Ok(aces)
}

/// The mask of an allow or deny ACE and where its SID starts, from its `bytes`: the header, the mask, then for an
/// object ACE its flags and the GUIDs that they say are present, then the SID. Fails, saying what is too small, if any
/// of these reaches past the ACE.
fn layout_of(bytes: &[u8], object: bool) -> Result<(u32, usize), &'static str> {
    const HEADER: usize = size_of::<ACE_HEADER>();
    const GUID: usize = 16;
    // Revision, sub-authority count and the 6-byte authority: the SID's fixed part.
    const SID_FIXED: usize = 8;
    let word = |at: usize| -> Option<u32> { Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?)) };
    let mask = word(HEADER).ok_or("too small for its mask")?;
    let mut sid_at = HEADER + 4;
    if object {
        let flags = word(sid_at).ok_or("too small for its object flags")?;
        sid_at += 4
            + GUID * usize::from(flags & ACE_OBJECT_TYPE_PRESENT != 0)
            + GUID * usize::from(flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0);
    }
    let fixed = bytes.get(sid_at..sid_at + SID_FIXED).ok_or("too small for its SID")?;
    // A SID is its fixed part and one 32-bit word for each sub-authority.
    let len = SID_FIXED + 4 * usize::from(fixed[1]);
    if sid_at + len > bytes.len() {
        return Err("too small for its SID's sub-authorities");
    }
    Ok((mask, sid_at))
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

    /// What to call this SID for a person: the account or group it names, as `DOMAIN\Name` (`Name` for a well-known one
    /// such as Everyone), else the SID as `S-1-5-...`. Only a SID that this machine answers for is looked up
    /// (`is_local`: well-known, built-in and service SIDs, and those of the machine's own accounts); every other, a
    /// domain account, a logon session or an Entra ID SID, is shown as its text, so a lookup never waits on a domain
    /// controller.
    pub fn label(&self) -> String {
        let name = is_local(self, machine_domain()).then(|| self.account_name()).flatten();
        name.unwrap_or_else(|| {
            self.text()
                .unwrap_or_else(|err| format!("an SID that cannot be read ({err})"))
        })
    }

    /// The name of the account or group that Windows has for this SID (`LookupAccountSidW` of the local system), if
    /// it has one.
    fn account_name(&self) -> Option<String> {
        let (mut name_len, mut domain_len, mut kind) = (0u32, 0u32, 0);
        // SAFETY: a null buffer of size 0 asks for the sizes, which the call writes through the live out pointers.
        let sized = unsafe {
            LookupAccountSidW(
                null(),
                self.as_psid(),
                null_mut(),
                &mut name_len,
                null_mut(),
                &mut domain_len,
                &mut kind,
            )
        };
        // SAFETY: only reads the thread's last error.
        if sized != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        let (mut name, mut domain) = (vec![0u16; name_len as usize], vec![0u16; domain_len as usize]);
        // SAFETY: the buffers hold the lengths that are passed, which Windows asked for.
        let found = unsafe {
            LookupAccountSidW(
                null(),
                self.as_psid(),
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        };
        if found == 0 || [SidTypeDeletedAccount, SidTypeInvalid, SidTypeUnknown].contains(&kind) {
            return None;
        }
        // On success the lengths exclude the NUL.
        let (name, domain) = (
            String::from_utf16_lossy(&name[..name_len as usize]),
            String::from_utf16_lossy(&domain[..domain_len as usize]),
        );
        Some(if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        })
    }

    /// The identifier authority and the sub-authorities of the SID.
    fn parts(&self) -> (u64, Vec<u32>) {
        let sid = self.as_psid();
        // SAFETY: `self` is a valid SID; the pointers Windows returns point into it, and the sub-authority indexes are
        // below its count.
        unsafe {
            let authority = (*GetSidIdentifierAuthority(sid))
                .Value
                .iter()
                .fold(0, |all, byte| all << 8 | u64::from(*byte));
            let count = u32::from(*GetSidSubAuthorityCount(sid));
            (authority, (0..count).map(|at| *GetSidSubAuthority(sid, at)).collect())
        }
    }

    /// Whether this SID and `other` are SIDs of one domain (`EqualDomainSid`); false if either is not a domain's.
    fn in_domain_of(&self, other: &Sid) -> bool {
        let mut equal = 0;
        // SAFETY: both are valid SIDs, and `equal` is where the answer goes.
        let done = unsafe { EqualDomainSid(self.as_psid(), other.as_psid(), &mut equal) };
        done != 0 && equal != 0
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

/// The domain SID of this machine's own accounts, kept once it has been read.
static MACHINE_DOMAIN: OnceLock<Sid> = OnceLock::new();

/// The domain SID of this machine's own accounts (the local SAM), as Windows answers; None if it does not. A failed
/// read is not kept: the next call reads again.
fn machine_domain() -> Option<&'static Sid> {
    if let Some(sid) = MACHINE_DOMAIN.get() {
        return Some(sid);
    }
    read_machine_domain().map(|sid| MACHINE_DOMAIN.get_or_init(|| sid))
}

fn read_machine_domain() -> Option<Sid> {
    let attributes = LSA_OBJECT_ATTRIBUTES {
        Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    let mut policy: LSA_HANDLE = 0;
    // SAFETY: `attributes` is initialized, and `policy` is where the handle goes.
    let opened = unsafe { LsaOpenPolicy(null(), &attributes, POLICY_VIEW_LOCAL_INFORMATION as u32, &mut policy) };
    if opened != STATUS_SUCCESS {
        return None;
    }
    let _policy = Policy(policy);
    let mut info = null_mut();
    // SAFETY: `policy` is open, and `info` is where Windows puts what it allocates.
    let status = unsafe { LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, &mut info) };
    let _info = LsaMemory(info);
    if status != STATUS_SUCCESS || info.is_null() {
        return None;
    }
    // SAFETY: this information class is a `POLICY_ACCOUNT_DOMAIN_INFO`, valid until freed; its SID is copied.
    let sid = unsafe { (*info.cast::<POLICY_ACCOUNT_DOMAIN_INFO>()).DomainSid };
    // SAFETY: a non-null SID in that structure is valid.
    (!sid.is_null()).then(|| unsafe { Sid::copy_of(sid) })
}

/// Whether this machine answers for `sid`, so that a lookup of it asks no other: only these, never "whatever is not
/// known to be foreign". Everyone (`S-1-1-0`), the local and creator authorities (`S-1-2-*`, `S-1-3-*`), the NT
/// AUTHORITY SIDs `S-1-5-1` to `S-1-5-20` but the logon sessions (`S-1-5-5-*`), BUILTIN (`S-1-5-32-*`), the service
/// SIDs (`S-1-5-80-*`, which the local LSA computes), and the SIDs of this machine's own account domain
/// (`machine_domain`; with none known, no domain SID is). A logon, Entra ID (`S-1-12-*`), capability (`S-1-15-*`) or
/// another domain's SID is not.
fn is_local(sid: &Sid, machine_domain: Option<&Sid>) -> bool {
    match sid.parts() {
        (1, subs) => subs == [0],
        (2 | 3, _) => true,
        (5, subs) => match subs.first() {
            Some(1..=4 | 6..=20 | 32 | 80) => true,
            Some(21) => machine_domain.is_some_and(|machine| sid.in_domain_of(machine)),
            _ => false,
        },
        _ => false,
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
