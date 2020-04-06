/// injector -- an executable responsible for running OVRServer_x64.exe
/// in debug mode and injecting injectee.dll
///
/// Usage:
///
/// One way to use this is to use global flags (see: gflags).
///
/// Create registry key
/// `HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/OVRServer_x64.exe`
/// and a `Debugger` string value =
/// `"path_to\injector.exe" "path_to\OVRServer_x64.exe"`.
/// This will run `injector.exe` as a debugger for `OVRServer_x64`,
/// which allows us to completely control it.
use std::env::{self, args_os};
use std::ffi::{OsString};
use std::os::windows::ffi::{OsStrExt};
use std::ptr::null_mut;

/// winapi module -- describing enough win32api surface to work with
#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
mod winapi {
    use std::ffi::{c_void};
    pub type BOOL = i32;
    pub type WORD = i16;
    pub type DWORD = i32;
    pub type LPVOID = *mut c_void;
    pub type LPCVOID = *mut c_void;
    pub type HANDLE = *mut c_void;
    pub type LPBYTE = *mut u8;
    pub type LPSTR = *mut u8;
    pub type LPWSTR = *mut u16;

    pub type THREAD_START_ROUTINE = extern "C" fn(lpThreadParameter: LPVOID) -> DWORD;

    #[repr(C)]
    pub struct SECURITY_ATTRIBUTES {
      pub nLength: DWORD,
      pub lpSecurityDescriptor: LPVOID,
      pub bInheritHandle: BOOL,
    }

    #[repr(C)]
    pub struct STARTUPINFOW {
      pub cb:                DWORD,
      pub lpReserved:        LPWSTR,
      pub lpDesktop:         LPWSTR,
      pub lpTitle:           LPWSTR,
      pub dwX:               DWORD,
      pub dwY:               DWORD,
      pub dwXSize:           DWORD,
      pub dwYSize:           DWORD,
      pub dwXCountChars:     DWORD,
      pub dwYCountChars:     DWORD,
      pub dwFillAttribute:   DWORD,
      pub dwFlags:           DWORD,
      pub wShowWindow:       WORD,
      pub cbReserved2:       WORD,
      pub lpReserved2:       LPBYTE,
      pub hStdInput:         HANDLE,
      pub hStdOutput:        HANDLE,
      pub hStdError:         HANDLE,
    }

    #[repr(C)]
    pub struct PROCESS_INFORMATION {
      pub hProcess:    HANDLE,
      pub hThread:     HANDLE,
      pub dwProcessId: DWORD,
      pub dwThreadId:  DWORD,
    }

    extern "C" {
        pub fn CreateProcessW(
            lpApplicationName: LPWSTR,
            lpCommandLine: LPWSTR,
            lpProcessAttributes: *mut SECURITY_ATTRIBUTES,
            lpThreadAttributes: *mut SECURITY_ATTRIBUTES,
            bInheritHandles: BOOL,
            dwCreationFlags: DWORD,
            lpEnvironment: *mut LPWSTR,
            lpCurrentDirectory: LPWSTR,
            lpStartupInfo: *mut STARTUPINFOW,
            lpProcessInformation: *mut PROCESS_INFORMATION,
            ) -> BOOL;
        pub fn WaitForSingleObject(
            handle: HANDLE,
            time: DWORD,
            ) -> DWORD;
        pub fn VirtualAllocEx(
            hProcess: HANDLE,
            lpAddress: LPVOID,
            dwSize: usize,
            flAllocationType: DWORD,
            flProtect: DWORD,
            ) -> LPVOID;
        pub fn WriteProcessMemory(
            hProcess: HANDLE,
            lpBaseAddress: LPCVOID,
            lpBuffer: LPCVOID,
            nSize: usize,
            lpNumberOfBytesWritten: *mut usize,
            ) -> BOOL;
        pub fn GetModuleHandleA(
            lpModuleName: LPSTR,
            ) -> HANDLE;
        pub fn GetModuleHandleW(
            lpModuleName: LPWSTR,
            ) -> HANDLE;
        pub fn GetProcAddress(
            hModule: HANDLE,
            lpProcName: LPSTR,
            ) -> LPVOID;
        pub fn CreateRemoteThread(
            hProcess: HANDLE,
            lpThreadAttributes: *mut SECURITY_ATTRIBUTES,
            dwStackSize: usize,
            lpStartAddress: *const THREAD_START_ROUTINE,
            lpParameter: LPVOID,
            dwCreationFlags: DWORD,
            lpThreadId: *mut DWORD
            ) -> HANDLE;
        pub fn ResumeThread(
            hThread: HANDLE,
            ) -> DWORD;
        pub fn DebugActiveProcessStop(
            dwProcessId: DWORD
            ) -> BOOL;
    }

    pub const CREATE_SUSPENDED: DWORD = 0x00000004;
    pub const DEBUG_ONLY_THIS_PROCESS: DWORD = 0x00000002;
    pub const DEBUG_PROCESS: DWORD = 0x00000002;
    pub const INFINITE: DWORD = !0;
    pub const PAGE_READWRITE: DWORD = 0x04;
    pub const MEM_RESERVE: DWORD = 0x00002000;
    pub const MEM_COMMIT: DWORD = 0x00001000;
}
use winapi::*;

/// Return size of slice in bytes
fn size_of_slice<T>(slice: &[T]) -> usize {
    std::mem::size_of::<T>() * slice.len()
}

/// enum that defines how we should start the process.
/// This influences dwCreationFlags in CreateProcessW.
enum RunMode {
    /// Start process with debug flag
    Debug,
    /// Start a suspended process
    Suspend,
}

const RUN_MODE: RunMode = RunMode::Debug;

fn main() {
    unsafe {
        let argv: Vec<OsString> = args_os().collect();
        if argv.len() <= 1 {
            println!("no arguments :(");
            return;
        }

        let mut path: Vec<u16> = argv[1].encode_wide().collect();
        path.push(0);

        // Concatenate arguments to create command line
        // TODO: this does not handle quotes, that doesn't seem to be necessary
        let mut args = Vec::<u16>::new();
        for arg in &argv[1..] {
            if !args.is_empty() {
                args.push(32);
            }
            println!("new arg: {:?}", arg);
            args.extend(arg.encode_wide());
        }
        args.push(0);
        println!("argv: {:?}", argv);
        println!("path: {:?}", argv[1]);

        // Try SSL_KEYLOG_FILE env var, like a feature we're trying to mimick
        // The injectee DLL will read this env var
        if let Some(path) = env::var_os("SSL_KEYLOG_FILE") {
            println!("passing through SSL_KEYLOG_FILE={:?}", path);
        } else {
            // That was not provided, use the directory of the executable
            if let Ok(mut path) = env::current_exe() {
                path.pop();
                path.push("ssl_keylog.txt");
                println!("putting keylog near currently running binary={:?}", path);
                env::set_var("SSL_KEYLOG_FILE", path);
            } else {
                println!("could not get SSL_KEYLOG_FILE and current program path?..");
            }
        }

        let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;

        let start_mode = match RUN_MODE {
            RunMode::Debug => DEBUG_ONLY_THIS_PROCESS,
            RunMode::Suspend => CREATE_SUSPENDED,
        };

        // Create a suspended or debugged process
        let result = CreateProcessW(
            path.as_mut_ptr(),
            args.as_mut_ptr(),
            null_mut::<SECURITY_ATTRIBUTES>(),
            null_mut::<SECURITY_ATTRIBUTES>(),
            1,
            start_mode,
            null_mut(),
            null_mut(),
            &mut startup_info as *mut STARTUPINFOW,
            &mut proc_info as *mut PROCESS_INFORMATION);

        println!("CreateProcessW result = {}", result);

        let mut library_path: Vec<u16>;

        // assume injectee.dll is near currently running executable
        if let Ok(mut path) = env::current_exe() {
            path.pop();
            path.push("injectee.dll");
            println!("library path: {:?}", path);
            library_path = path.as_os_str().encode_wide().collect();
            library_path.push(0);
        } else {
            println!("could not get current path!");
            return;
        }

        // DLL injection
        let kernel32_mod = GetModuleHandleA(b"Kernel32.dll\0".as_ptr() as _);
        println!("kernel32 module handle: {}", kernel32_mod as usize);

        // 1) kernel32.dll has the same location in all running processes
        let load_library_ptr = GetProcAddress(
            kernel32_mod, b"LoadLibraryW\0".as_ptr() as _);
        println!("load_library_ptr: {}", load_library_ptr as usize);

        // All following operations require us to have certain access
        // to the process, but since we started it in debug mode,
        // we probably have that access.
        //
        // 2) Allocate memory for DLL path in the target process
        let name_ptr = VirtualAllocEx(
            proc_info.hProcess, null_mut(), size_of_slice(&library_path) as _,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        println!("DLL name ptr: {}", name_ptr as usize);

        // 3) Write library path to the recently allocated memory
        let result = WriteProcessMemory(
            proc_info.hProcess, name_ptr, library_path.as_ptr() as _,
            size_of_slice(&library_path) as _, null_mut());
        println!("WriteProcessMemory result: {}", result);

        // 4) CreateRemoteThread with kernel32.LoadLibraryW as a starting point
        //    and injectee DLL path as its only argument.
        let mut threadid = 0;
        let thread_handle = CreateRemoteThread(
                proc_info.hProcess, null_mut(), 0,
                load_library_ptr as _, name_ptr, 0, &mut threadid as _);
        println!("CreateRemoteThread result: {}", thread_handle as usize);

        // If we started the process in debug mode, the recently
        // created thread won't run, so ignore this code for now
        // let result = WaitForSingleObject(thread_handle, INFINITE);
        // println!("WaitForSingleObject result = {}", result);

        // Finally, resume the process, depending on how we started it
        match RUN_MODE {
            RunMode::Debug => {
                let result = DebugActiveProcessStop(proc_info.dwProcessId);
                println!("DebugActiveProcessStop result: {}", result as usize);
            }
            RunMode::Suspend => {
                let result = ResumeThread(proc_info.hThread);
                println!("ResumeThread result: {}", result);
            }
        }

        // After everything is done, wait for the project to die.
        // TODO: pass events so that the service can be stopped normally.
        let result = WaitForSingleObject(proc_info.hProcess, INFINITE);
        println!("WaitForSingleObject result = {}", result);
    }
}
