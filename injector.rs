use std::ptr::null_mut;
use std::env::args_os;
use std::ffi::{OsString};
use std::os::windows::ffi::{OsStrExt};

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

enum RunMode {
    Debug,
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

        let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;

        let start_mode = match RUN_MODE {
            RunMode::Debug => DEBUG_ONLY_THIS_PROCESS,
            RunMode::Suspend => CREATE_SUSPENDED,
        };

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
        const LIB_PATH: &[u8] = b"g:\\projects\\wrap\\injectee.dll\0";

        let kernel32_mod = GetModuleHandleA(b"Kernel32.dll\0".as_ptr() as _);
        println!("kernel32 module handle: {}", kernel32_mod as usize);

        let load_library_ptr = GetProcAddress(kernel32_mod, b"LoadLibraryA\0".as_ptr() as _);
        println!("load_library_ptr: {}", load_library_ptr as usize);

        let name_ptr = VirtualAllocEx(proc_info.hProcess, null_mut(), LIB_PATH.len(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        println!("dll name ptr: {}", name_ptr as usize);

        let result = WriteProcessMemory(proc_info.hProcess, name_ptr, LIB_PATH.as_ptr() as _, LIB_PATH.len() as _, null_mut());
        println!("WriteProcessMemory result: {}", result);

        let mut threadid = 0;
        let thread_handle = CreateRemoteThread(proc_info.hProcess, null_mut(), 0, load_library_ptr as _, name_ptr, 0, &mut threadid as _);
        println!("CreateRemoteThread result: {}", thread_handle as usize);

        // let result = WaitForSingleObject(thread_handle, INFINITE);
        // println!("WaitForSingleObject result = {}", result);

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

        let result = WaitForSingleObject(proc_info.hProcess, INFINITE);
        println!("WaitForSingleObject result = {}", result);
    }
}
