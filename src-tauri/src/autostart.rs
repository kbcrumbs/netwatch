//! Start at login through a Task Scheduler task. NetWatch needs admin rights,
//! and a task set to "run with highest privileges" gets them at logon without
//! a UAC prompt, which a Run-key entry can't.

use std::os::windows::process::CommandExt;
use std::process::Command;

const TASK: &str = "NetWatch";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn schtasks(args: &[&str]) -> Result<(), String> {
    let out = Command::new("schtasks.exe")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn enabled() -> bool {
    schtasks(&["/Query", "/TN", TASK]).is_ok()
}

pub fn set(on: bool) -> Result<(), String> {
    if !on {
        return if enabled() { schtasks(&["/Delete", "/TN", TASK, "/F"]) } else { Ok(()) };
    }
    create(TASK)
}

fn create(name: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let user = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").unwrap_or_default(),
        std::env::var("USERNAME").map_err(|e| e.to_string())?
    );
    let xml = task_xml(&exe.to_string_lossy(), &user);
    // schtasks reads task XML as UTF-16 with a byte-order mark.
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    let path = std::env::temp_dir().join("netwatch-task.xml");
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    let result = schtasks(&["/Create", "/TN", name, "/XML", &path.to_string_lossy(), "/F"]);
    let _ = std::fs::remove_file(&path);
    result
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A logon task for `user` that runs `exe --minimized` elevated, with no time
/// limit and regardless of battery state (the scheduler's defaults stop tasks
/// after three days and skip them on battery).
fn task_xml(exe: &str, user: &str) -> String {
    let (exe, user) = (escape(exe), escape(user));
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Starts NetWatch in the tray when you sign in.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>--minimized</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_xml_is_escaped_and_unlimited() {
        let xml = task_xml(r"C:\Apps\R&D <tools>\netwatch.exe", r"EXAMPLE\someone");
        assert!(xml.contains(r"<Command>C:\Apps\R&amp;D &lt;tools&gt;\netwatch.exe</Command>"));
        assert!(xml.contains(r"<UserId>EXAMPLE\someone</UserId>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(xml.contains("<Arguments>--minimized</Arguments>"));
    }

    /// Registers a throwaway task to prove the scheduler accepts the XML, then
    /// deletes it. Needs an elevated shell: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn scheduler_accepts_task() {
        let name = "NetWatch-selftest";
        create(name).expect("task registered");
        let shown = Command::new("schtasks.exe").args(["/Query", "/TN", name, "/XML"]).output().unwrap();
        let _ = schtasks(&["/Delete", "/TN", name, "/F"]);
        let xml = String::from_utf8_lossy(&shown.stdout);
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(schtasks(&["/Query", "/TN", name]).is_err(), "cleaned up");
    }
}
