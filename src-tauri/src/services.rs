//! Maps PIDs to the Windows services running inside them, so shared hosts
//! like svchost.exe show which service actually owns a connection.

use std::collections::HashMap;

use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};

/// PID -> display names of the running services hosted by that process.
pub fn by_pid() -> HashMap<u32, Vec<String>> {
    let mut map: HashMap<u32, Vec<String>> = HashMap::new();
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) else {
            return map;
        };
        let mut needed = 0u32;
        let mut count = 0u32;
        // Probe for the size, then read; retry if services started in between.
        // A u64 buffer keeps the entries' pointer fields aligned.
        let mut buf: Vec<u64> = Vec::new();
        for _ in 0..4 {
            let bytes = std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len() * 8);
            let slice = if buf.is_empty() { None } else { Some(bytes) };
            let mut resume = 0u32;
            let ok = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                slice,
                &mut needed,
                &mut count,
                Some(&mut resume),
                PCWSTR::null(),
            )
            .is_ok();
            if ok && !buf.is_empty() {
                break;
            }
            count = 0;
            buf = vec![0u64; (needed as usize + 4096) / 8];
        }
        if count > 0 {
            let entries =
                std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for e in entries {
                let pid = e.ServiceStatusProcess.dwProcessId;
                if pid == 0 {
                    continue;
                }
                let name = e.lpDisplayName.to_string().or_else(|_| e.lpServiceName.to_string()).unwrap_or_default();
                if !name.is_empty() {
                    map.entry(pid).or_default().push(name);
                }
            }
            for names in map.values_mut() {
                names.sort();
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    map
}

#[cfg(test)]
mod tests {
    #[test]
    fn maps_service_hosts() {
        let map = super::by_pid();
        let total: usize = map.values().map(Vec::len).sum();
        println!("{} service host PIDs, {total} services", map.len());
        assert!(total > 10, "a running Windows box hosts many services");
    }
}
