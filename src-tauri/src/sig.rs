//! Authenticode verification. Checks the embedded signature first and falls
//! back to the system catalogs, which is how most Windows binaries are signed.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;

use serde::Serialize;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B0003u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B0001u32 as i32;

#[derive(Clone, Serialize, Debug)]
pub struct SigInfo {
    /// "signed", "unsigned", "invalid", "unknown" or "pending".
    pub status: &'static str,
    pub signer: Option<String>,
}

impl SigInfo {
    pub fn pending() -> Self {
        Self { status: "pending", signer: None }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn verify(path: &str) -> SigInfo {
    let wpath = wide(path);
    let (rc, signer) = unsafe { verify_embedded(&wpath) };
    if rc == 0 {
        return SigInfo { status: "signed", signer };
    }
    let no_embedded = matches!(
        rc,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN
    );
    if !no_embedded {
        return SigInfo { status: "invalid", signer: None };
    }
    match unsafe { verify_catalog(&wpath) } {
        Some((0, signer)) => SigInfo { status: "signed", signer },
        Some(_) => SigInfo { status: "invalid", signer: None },
        None if std::path::Path::new(path).exists() => SigInfo { status: "unsigned", signer: None },
        None => SigInfo { status: "unknown", signer: None },
    }
}

fn base_trust_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        // Offline check: no revocation lookups, no network fetches.
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    }
}

/// Runs WinVerifyTrust with state so the signer can be read, then closes it.
unsafe fn run_trust(data: &mut WINTRUST_DATA) -> (i32, Option<String>) {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    let rc = WinVerifyTrust(HWND::default(), &mut action, data as *mut _ as *mut c_void);
    let signer = if rc == 0 { signer_name(data.hWVTStateData) } else { None };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(HWND::default(), &mut action, data as *mut _ as *mut c_void);
    (rc, signer)
}

unsafe fn signer_name(state: HANDLE) -> Option<String> {
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return None;
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
    if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
        return None;
    }
    let cert = (*(*sgnr).pasCertChain).pCert;
    if cert.is_null() {
        return None;
    }
    let mut buf = [0u16; 256];
    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
    (n > 1).then(|| String::from_utf16_lossy(&buf[..n as usize - 1]))
}

unsafe fn verify_embedded(wpath: &[u16]) -> (i32, Option<String>) {
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..Default::default()
    };
    let mut data = base_trust_data();
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
    run_trust(&mut data)
}

/// None when the file is not listed in any system catalog.
unsafe fn verify_catalog(wpath: &[u16]) -> Option<(i32, Option<String>)> {
    for alg in [w!("SHA256"), PCWSTR::null()] {
        if let Some(r) = verify_catalog_with(wpath, alg) {
            return Some(r);
        }
    }
    None
}

unsafe fn verify_catalog_with(wpath: &[u16], alg: PCWSTR) -> Option<(i32, Option<String>)> {
    let file = CreateFileW(
        PCWSTR(wpath.as_ptr()),
        FILE_GENERIC_READ.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    .ok()?;

    let mut admin = 0isize;
    let alg_opt = (!alg.is_null()).then_some(alg);
    let mut result = None;

    if CryptCATAdminAcquireContext2(&mut admin, None, alg_opt.unwrap_or(PCWSTR::null()), None, None)
        .is_ok()
    {
        let mut hash = [0u8; 64];
        let mut hash_len = hash.len() as u32;
        if CryptCATAdminCalcHashFromFileHandle2(admin, file, &mut hash_len, Some(hash.as_mut_ptr()), None)
            .is_ok()
        {
            let cat = CryptCATAdminEnumCatalogFromHash(admin, &hash[..hash_len as usize], None, None);
            if cat != 0 {
                let mut info = CATALOG_INFO {
                    cbStruct: size_of::<CATALOG_INFO>() as u32,
                    ..Default::default()
                };
                if CryptCATCatalogInfoFromContext(cat, &mut info, 0).is_ok() {
                    let tag: String = hash[..hash_len as usize]
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect();
                    let wtag = wide(&tag);
                    let mut cat_info = WINTRUST_CATALOG_INFO {
                        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                        pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                        pcwszMemberTag: PCWSTR(wtag.as_ptr()),
                        pcwszMemberFilePath: PCWSTR(wpath.as_ptr()),
                        hMemberFile: file,
                        pbCalculatedFileHash: hash.as_mut_ptr(),
                        cbCalculatedFileHash: hash_len,
                        pcCatalogContext: null_mut(),
                        hCatAdmin: admin,
                        ..Default::default()
                    };
                    let mut data = base_trust_data();
                    data.dwUnionChoice = WTD_CHOICE_CATALOG;
                    data.Anonymous = WINTRUST_DATA_0 { pCatalog: &mut cat_info };
                    result = Some(run_trust(&mut data));
                }
                let _ = CryptCATAdminReleaseCatalogContext(admin, cat, 0);
            }
        }
        let _ = CryptCATAdminReleaseContext(admin, 0);
    }

    let _ = CloseHandle(file);
    result
}
