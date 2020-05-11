#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
/// winapi module -- describing enough win32api surface to work with

use std::ffi::{c_void};
pub type BOOL = i32;
pub type WORD = i16;
pub type DWORD = i32;
pub type HINSTANCE = *mut c_void;
pub type HANDLE = *mut c_void;
pub type LPVOID = *mut c_void;
pub type LPCVOID = *mut c_void;
pub type LPBYTE = *mut u8;
pub type LPSTR = *mut u8;
pub type LPWSTR = *mut u16;

pub type THREAD_START_ROUTINE = extern "C" fn(lpThreadParameter: LPVOID) -> DWORD;

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


#[repr(C)]
pub struct CREATE_PROCESS_DEBUG_INFO {
    pub hFile:                 HANDLE,
    pub hProcess:              HANDLE,
    pub hThread:               HANDLE,
    pub lpBaseOfImage:         LPVOID,
    pub dwDebugInfoFileOffset: DWORD,
    pub nDebugInfoSize:        DWORD,
    pub lpThreadLocalBase:     LPVOID,
    pub lpStartAddress:        *mut THREAD_START_ROUTINE,
    pub lpImageName:           LPVOID,
    pub fUnicode:              WORD,
}

#[repr(C)]
pub struct EXCEPTION_DEBUG_INFO {
    pub ExceptionRecord: EXCEPTION_RECORD,
    pub dwFirstChance: DWORD,
}

pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

#[derive(Debug)]
#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode:    DWORD,
    pub ExceptionFlags:   DWORD,
    pub ExceptionRecord:  *mut EXCEPTION_RECORD,
    pub ExceptionAddress: LPVOID,
    pub NumberParameters: DWORD,
    pub ExceptionInformation: [LPVOID; EXCEPTION_MAXIMUM_PARAMETERS],
}

#[repr(C)]
pub struct EXIT_PROCESS_DEBUG_INFO {
    pub dwExitCode: DWORD,
}

#[repr(C)]
pub union DEBUG_EVENT_U {
    pub Exception:         EXCEPTION_DEBUG_INFO,
    // pub CreateThread:      CREATE_THREAD_DEBUG_INFO,
    pub CreateProcessInfo: CREATE_PROCESS_DEBUG_INFO,
    // pub ExitThread:        EXIT_THREAD_DEBUG_INFO,
    pub ExitProcess:       EXIT_PROCESS_DEBUG_INFO,
    // pub LoadDll:           LOAD_DLL_DEBUG_INFO,
    // pub UnloadDll:         UNLOAD_DLL_DEBUG_INFO,
    // pub DebugString:       OUTPUT_DEBUG_STRING_INFO,
    // pub RipInfo:           RIP_INFO,
}

#[repr(C)]
pub struct DEBUG_EVENT {
    pub dwDebugEventCode: DWORD,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
    pub u: DEBUG_EVENT_U,
}

#[repr(C)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress:       LPVOID,
    pub AllocationBase:    LPVOID,
    pub AllocationProtect: DWORD,
    pub RegionSize:        usize,
    pub State:             DWORD,
    pub Protect:           DWORD,
    pub Type:              DWORD,
}

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
  pub nLength: DWORD,
  pub lpSecurityDescriptor: LPVOID,
  pub bInheritHandle: BOOL,
}

#[repr(C)]
pub struct MODULEINFO {
  pub lpBaseOfDll: LPVOID,
  pub SizeOfImage: DWORD,
  pub EntryPoint: LPVOID,
}


#[link(name = "Kernel32")]
extern "C" {
    pub fn GetStdHandle(
        nStdHandle: DWORD,
    ) -> HANDLE;

    pub fn WriteConsoleA(
        hConsoleOutput: HANDLE,
        lpBuffer: *mut u8,
        nNumberOfCharsToWrite: DWORD,
        lpNumberOfCharsWritten: *mut DWORD,
        lpReserved: LPVOID,
    ) -> BOOL;

    pub fn CreateFileA(
        lpFileName: LPSTR,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: *mut SECURITY_ATTRIBUTES,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
        ) -> HANDLE;

    pub fn GetModuleFileNameW(
        hModule: HANDLE,
        lpFileName: LPWSTR,
        dSize: DWORD,
        ) -> DWORD;

    pub fn GetModuleHandleA(
        lpModuleName: LPSTR,
        ) -> HANDLE;

    pub fn GetCurrentProcess() -> HANDLE;

    pub fn K32GetModuleInformation(
        hProcess:  HANDLE,
        hModule:   HANDLE,
        lpmodinfo: *mut MODULEINFO,
        cb:         DWORD,
        ) -> BOOL;

    pub fn VirtualProtect(
        lpAddress:     LPVOID,
        dwSize:        usize,
        flNewProtect:  DWORD,
        lpflOldProtect: *mut DWORD,
        ) -> BOOL;

    pub fn VirtualQuery(
        lpAddress: LPVOID,
        lpBuffer: *mut MEMORY_BASIC_INFORMATION,
        dwLength: usize,
        ) -> usize;

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

    pub fn ReadProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: LPCVOID,
        lpBuffer: LPCVOID,
        nSize: usize,
        lpNumberOfBytesRead: *mut usize,
        ) -> BOOL;

    pub fn WriteProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: LPCVOID,
        lpBuffer: LPCVOID,
        nSize: usize,
        lpNumberOfBytesWritten: *mut usize,
        ) -> BOOL;

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

    pub fn WaitForDebugEvent(
        lpDebugEvent: *mut DEBUG_EVENT,
        dwMilliseconds: DWORD,
        ) -> BOOL;

    pub fn ContinueDebugEvent(
        dwProcessId: DWORD,
        dwThreadId: DWORD,
        dwContinueStatus: DWORD,
        ) -> BOOL;

    pub fn GetFinalPathNameByHandleW(
        hFile:        HANDLE,
        lpszFilePath: LPWSTR,
        cchFilePath:  DWORD,
        dwFlags:      DWORD,
        ) -> DWORD;

    pub fn OpenProcess(
        dwDesiredAccess: DWORD,
        bInheritHandle:  BOOL,
        dwProcessId:     DWORD,
        ) -> HANDLE;

    pub fn CloseHandle(handle: HANDLE) -> BOOL;

    pub fn VirtualQueryEx(
        hProcess: HANDLE,
        lpAddress: LPVOID,
        lpBuffer: *mut MEMORY_BASIC_INFORMATION,
        dwLength: usize,
        ) -> usize;

    pub fn K32GetModuleBaseNameA(
        hProcess:   HANDLE,
        hModule:    HANDLE,
        lpBaseName: LPSTR,
        nSize:      DWORD,
        ) -> DWORD;
}

pub const STD_OUTPUT_HANDLE: DWORD = -11;
pub const INVALID_HANDLE_VALUE: HANDLE = !0 as _;
pub const DLL_PROCESS_DETACH: DWORD = 0;
pub const DLL_PROCESS_ATTACH: DWORD = 1;
pub const DLL_THREAD_ATTACH: DWORD = 2;
pub const DLL_THREAD_DETACH: DWORD = 3;

pub const GENERIC_READ    : DWORD = -0x80000000;
pub const GENERIC_WRITE   : DWORD = 0x40000000;
pub const GENERIC_EXECUTE : DWORD = 0x20000000;
pub const GENERIC_ALL     : DWORD = 0x10000000;
pub const FILE_SHARE_WRITE: DWORD = 2;

pub const CREATE_NEW: DWORD = 1;
pub const CREATE_ALWAYS: DWORD = 2;
pub const OPEN_EXISTING: DWORD = 3;
pub const OPEN_ALWAYS: DWORD = 4;
pub const TRUNCATE_EXISTING: DWORD = 5;

pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_READWRITE: DWORD = 0x04;

pub const CREATE_SUSPENDED: DWORD = 0x00000004;
pub const DEBUG_ONLY_THIS_PROCESS: DWORD = 0x00000002;
pub const DEBUG_PROCESS: DWORD = 0x00000001;
pub const INFINITE: DWORD = !0;
pub const MEM_RESERVE: DWORD = 0x00002000;
pub const MEM_COMMIT: DWORD = 0x00001000;


const fn bad_const(c: u32) -> i32 {
    i32::from_ne_bytes(c.to_ne_bytes())
}

pub const DBG_CONTINUE: DWORD = 0x00010002;
pub const DBG_CONTROL_C: DWORD = 0x40010005;
pub const DBG_EXCEPTION_NOT_HANDLED: DWORD = bad_const(0x80010001);
pub const DBG_REPLY_LATER: DWORD = 0x40010001;

pub const EXCEPTION_DEBUG_EVENT: DWORD = 1;
pub const CREATE_THREAD_DEBUG_EVENT: DWORD = 2;
pub const CREATE_PROCESS_DEBUG_EVENT: DWORD = 3;
pub const EXIT_THREAD_DEBUG_EVENT: DWORD = 4;
pub const EXIT_PROCESS_DEBUG_EVENT: DWORD = 5;
pub const LOAD_DLL_DEBUG_EVENT: DWORD = 6;
pub const UNLOAD_DLL_DEBUG_EVENT: DWORD = 7;
pub const OUTPUT_DEBUG_STRING_EVENT: DWORD = 8;
pub const RIP_EVENT: DWORD = 9;

pub const EXCEPTION_ACCESS_VIOLATION        : DWORD = bad_const(0xC0000005);
pub const EXCEPTION_DATATYPE_MISALIGNMENT   : DWORD = bad_const(0x80000002);
pub const EXCEPTION_BREAKPOINT              : DWORD = bad_const(0x80000003);
pub const EXCEPTION_SINGLE_STEP             : DWORD = bad_const(0x80000004);
pub const EXCEPTION_ARRAY_BOUNDS_EXCEEDED   : DWORD = bad_const(0xC000008C);
pub const EXCEPTION_FLT_DENORMAL_OPERAND    : DWORD = bad_const(0xC000008D);
pub const EXCEPTION_FLT_DIVIDE_BY_ZERO      : DWORD = bad_const(0xC000008E);
pub const EXCEPTION_FLT_INEXACT_RESULT      : DWORD = bad_const(0xC000008F);
pub const EXCEPTION_FLT_INVALID_OPERATION   : DWORD = bad_const(0xC0000090);
pub const EXCEPTION_FLT_OVERFLOW            : DWORD = bad_const(0xC0000091);
pub const EXCEPTION_FLT_STACK_CHECK         : DWORD = bad_const(0xC0000092);
pub const EXCEPTION_FLT_UNDERFLOW           : DWORD = bad_const(0xC0000093);
pub const EXCEPTION_INT_DIVIDE_BY_ZERO      : DWORD = bad_const(0xC0000094);
pub const EXCEPTION_INT_OVERFLOW            : DWORD = bad_const(0xC0000095);
pub const EXCEPTION_PRIV_INSTRUCTION        : DWORD = bad_const(0xC0000096);
pub const EXCEPTION_IN_PAGE_ERROR           : DWORD = bad_const(0xC0000006);
pub const EXCEPTION_ILLEGAL_INSTRUCTION     : DWORD = bad_const(0xC000001D);
pub const EXCEPTION_NONCONTINUABLE_EXCEPTION: DWORD = bad_const(0xC0000025);
pub const EXCEPTION_STACK_OVERFLOW          : DWORD = bad_const(0xC00000FD);
pub const EXCEPTION_INVALID_DISPOSITION     : DWORD = bad_const(0xC0000026);
pub const EXCEPTION_GUARD_PAGE              : DWORD = bad_const(0x80000001);
pub const EXCEPTION_INVALID_HANDLE          : DWORD = bad_const(0xC0000008);

pub const STANDARD_RIGHTS_REQUIRED: DWORD = 0x000F0000;
pub const SYNCHRONIZE: DWORD = 0x00100000;
pub const PROCESS_DUP_HANDLE       : DWORD = 0x0040;
pub const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
pub const PROCESS_SUSPEND_RESUME   : DWORD = 0x0800;
pub const PROCESS_TERMINATE        : DWORD = 0x0001;
pub const PROCESS_VM_READ          : DWORD = 0x0010;
pub const PROCESS_ALL_ACCESS: DWORD = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;
