#![windows_subsystem = "windows"]

extern crate winapi;
extern crate windows_service;
use winapi::um::winnt::TokenPrimary;
use std::ffi::{OsStr, OsString};
use std::ptr::null_mut;
use std::sync::mpsc;
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::processthreadsapi::{CreateProcessAsUserW, OpenProcessToken, GetCurrentProcess, STARTUPINFOW};
use winapi::um::securitybaseapi::{AdjustTokenPrivileges, DuplicateTokenEx};
use winapi::um::userenv::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use winapi::um::winnt::{HANDLE, LUID, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_ASSIGN_PRIMARY, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES};
use winapi::um::winbase::WTSGetActiveConsoleSessionId;
use winapi::um::winuser::{SW_SHOW};
use windows_service::{
    define_windows_service, service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher::{self},
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::TOKEN_ADJUST_DEFAULT;
use winapi::um::winbase::{LookupPrivilegeValueW, STARTF_USESHOWWINDOW };
use winapi::um::winbase::CREATE_UNICODE_ENVIRONMENT;
use winapi::um::winnt::TOKEN_ALL_ACCESS;
use winapi::um::winnt::SecurityImpersonation;
use winapi::um::winnt::TokenSessionId;
use core::ffi::c_void;
use winapi::um::processthreadsapi::PROCESS_INFORMATION;
use std::error::Error;
use winapi::um::winnt::SECURITY_IMPERSONATION_LEVEL;
use core::mem;
define_windows_service!(ffi_service_main, service_main);
const PRIVILEGES: &[&str] = &[
    "SeAssignPrimaryTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeSecurityPrivilege",
    "SeSystemtimePrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeShutdownPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeUndockPrivilege",
    "SeManageVolumePrivilege",
    "SeCreateTokenPrivilege",
    "SeTrustedCredManAccessPrivilege",
    // Add any additional privileges you need to enable.
];
use winapi::um::winuser::SW_SHOWDEFAULT;
extern "system" {
    fn SetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: winapi::um::winnt::TOKEN_INFORMATION_CLASS,
        TokenInformation: *mut std::os::raw::c_void,
        TokenInformationLength: DWORD,
    ) -> winapi::shared::minwindef::BOOL;
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        // In a real application, use proper logging instead of println
        println!("Service failed: {:?}", e);
    }
}

fn run_service() -> windows_service::Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    let status_handle = service_control_handler::register("elevation_service", move |control_event| {
        match control_event {
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            },
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    // Enable necessary privileges here
    for &privilege in PRIVILEGES.iter() {
        if let Err(e) = enable_privilege(privilege) {
            println!("Failed to enable privilege {}: {:?}", privilege, e); // Consider proper logging
        }
    }

    // Attempt to start the GUI process with elevated privileges
    match start_gui_with_elevated_privileges() {
        Ok(pid) => println!("Started GUI process with PID: {}", pid),
        Err(e) => println!("Failed to start GUI with elevated privileges: {:?}", e),
    }

    // Wait for the shutdown signal
    let _ = shutdown_rx.recv();

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(), // Corrected from NONE to empty()
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

fn enable_privilege(privilege_name: &str) -> Result<(), u32> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return Err(GetLastError());
        }

        let mut luid = LUID { LowPart: 0, HighPart: 0 };

        let privilege_name_wide: Vec<u16> = OsStr::new(privilege_name).encode_wide().chain(std::iter::once(0)).collect();
        if LookupPrivilegeValueW(null_mut(), privilege_name_wide.as_ptr(), &mut luid) == 0 {
            return Err(GetLastError());
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }; 1],
        };

        if AdjustTokenPrivileges(token, FALSE, &mut tp as *mut _, 0, null_mut(), null_mut()) == 0 {

            return Err(GetLastError());
        }
    }

    Ok(())
}

fn start_gui_with_elevated_privileges() -> Result<u32, Box<dyn Error>> {
    unsafe {
        // Open a handle to the current process token
        let current_process = GetCurrentProcess();
        let mut current_process_token: HANDLE = null_mut();
        if OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut current_process_token) == 0 {
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        // Duplicate the token with the desired access
        let mut duplicated_token: HANDLE = null_mut();
        if DuplicateTokenEx(current_process_token, TOKEN_ALL_ACCESS, null_mut(), SecurityImpersonation as SECURITY_IMPERSONATION_LEVEL, TokenPrimary, &mut duplicated_token) == 0 {
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        // Retrieve the session ID for the active console session
        let session_id = WTSGetActiveConsoleSessionId();
        if session_id == 0xFFFFFFFF {
            return Err("No active session found".into());
        }

        // Set the session ID on the duplicated token
        if SetTokenInformation(
            duplicated_token,
            TokenSessionId,
            &session_id as *const _ as *mut _,
            mem::size_of::<DWORD>() as DWORD,
        ) == 0
        {
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        // Create an environment block for the new process
        let mut env_block: *mut c_void = null_mut();
        if CreateEnvironmentBlock(&mut env_block, duplicated_token, FALSE) == 0 {
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        // Set up the STARTUPINFO structure
        let mut startup_info: STARTUPINFOW = mem::zeroed();
        startup_info.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
        let desktop = OsStr::new("winsta0\\default").encode_wide().chain(Some(0)).collect::<Vec<_>>();
        startup_info.lpDesktop = desktop.as_ptr() as *mut _;
        startup_info.dwFlags = STARTF_USESHOWWINDOW;
        startup_info.wShowWindow = SW_SHOW as u16;

        // Specify the command line for the process
        let cmdline = OsStr::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe").encode_wide().chain(Some(0)).collect::<Vec<_>>();

        // Create the process as the user
        let mut process_info: PROCESS_INFORMATION = mem::zeroed();
        if CreateProcessAsUserW(
            duplicated_token,
            null_mut(),
            cmdline.as_ptr() as *mut _,
            null_mut(),
            null_mut(),
            FALSE,
            CREATE_UNICODE_ENVIRONMENT,
            env_block,
            null_mut(),
            &mut startup_info,
            &mut process_info,
        ) == 0
        {
            DestroyEnvironmentBlock(env_block);
            return Err(Box::new(std::io::Error::last_os_error()));
        }

        DestroyEnvironmentBlock(env_block);

        Ok(process_info.dwProcessId)
    }
}



fn main() -> windows_service::Result<()> {
    service_dispatcher::start("elevation_service", ffi_service_main)?;
    Ok(())
}
