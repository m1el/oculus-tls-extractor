#![feature(untagged_unions)]
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
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::collections::{HashMap, HashSet};
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

    pub const CREATE_SUSPENDED: DWORD = 0x00000004;
    pub const DEBUG_ONLY_THIS_PROCESS: DWORD = 0x00000002;
    pub const DEBUG_PROCESS: DWORD = 0x00000001;
    pub const INFINITE: DWORD = !0;
    pub const PAGE_READWRITE: DWORD = 0x04;
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
}
use winapi::*;

/// Return size of slice in bytes
fn size_of_slice<T>(slice: &[T]) -> usize {
    std::mem::size_of::<T>() * slice.len()
}

/// enum that defines how we should start the process.
/// This influences dwCreationFlags in CreateProcessW.
#[allow(dead_code)]
enum RunMode {
    /// Start process with debug flag
    Debug,
    /// Start process and debug its children
    DebugAll,
    /// Start a suspended process
    Suspend,
}

/// Given a handle, find its path
unsafe fn path_for_handle(handle: HANDLE) -> PathBuf {
    let mut buf = vec![0u16; 1024];
    let rv = GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as i32, 0);
    assert!(rv > 0 && rv < 1024, "whoa, what's wrong with this path");
    PathBuf::from(OsString::from_wide(&buf[0..(rv as usize)]))
}

/// Dump process memory and module name at location
unsafe fn dump_memory(output: &mut File, process: HANDLE, ptr: LPVOID, size: usize) {
    let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
    // VirtualQueryEx will tell us the base of allocation, which is going
    // to be the same as module handle in which the code is running.
    // This fails if the exception location is outside of the module.
    let rv = VirtualQueryEx(process, ptr, &mut mbi, mbi_size);
    assert!(rv == mbi_size, "MEMORY_BASIC_INFORMATION bad size?");
    let module = mbi.AllocationBase;
    // Get module name given its handle
    if module != null_mut() {
        let mut buf = vec![0_u8; 512];
        let sz = K32GetModuleBaseNameA(process, module, buf.as_mut_ptr(), buf.len() as i32);
        buf.truncate(sz as usize);
        writeln!(output, "module name: {:?}", std::str::from_utf8(&buf)).unwrap();
    }
    let mut buf = vec![0u8; size];
    let mut bytes_read = 0;
    ReadProcessMemory(process, ptr, buf.as_mut_ptr() as LPVOID, size, &mut bytes_read);
    buf.truncate(bytes_read);
    writeln!(output, "bytes = {:x?}", buf).unwrap();
}

/// Inject a dll into a process specified by `process` handle
unsafe fn inject_snoop_dll(process: HANDLE, dll_path: &[u16]) {
    let kernel32_mod = GetModuleHandleA(b"Kernel32.dll\0".as_ptr() as _);
    assert!(kernel32_mod != null_mut(), "Get Kernel32.dll handle failed?");

    // 1) kernel32.dll has the same address space in all running processes
    let load_library_ptr = GetProcAddress(
        kernel32_mod, b"LoadLibraryW\0".as_ptr() as _);
    assert!(load_library_ptr != null_mut(),
        "Get pointer to LoadLibraryW failed?");

    // All following operations require us to have certain access
    // to the process, but since we started it in debug mode,
    // we probably have that access.
    //
    // 2) Allocate memory for DLL path in the target process
    let name_ptr = VirtualAllocEx(
        process, null_mut(), size_of_slice(dll_path) as _,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    assert!(name_ptr != null_mut(), "VirtualAllocEx failed");

    // 3) Write library path to the recently allocated memory
    let result = WriteProcessMemory(
        process, name_ptr, dll_path.as_ptr() as _,
        size_of_slice(dll_path) as _, null_mut());
    assert!(result != 0, "WriteProcessMemory failed");

    // 4) CreateRemoteThread with kernel32.LoadLibraryW as a starting point
    //    and injectee DLL path as its only argument.
    let mut threadid = 0;
    let thread_handle = CreateRemoteThread(
            process, null_mut(), 0,
            load_library_ptr as _, name_ptr, 0, &mut threadid as _);
    assert!(thread_handle != null_mut(), "CreateRemoteThread failed");
    println!("injected successfully?");
}


struct Injector {
    /// a mode in which we're going to run the injector
    run_mode: RunMode,
    /// path to injectee dll
    dll_path: Vec<u16>,
    /// output file, used for loggin
    output: File,
    /// A map between process id and (process handle, path to executable)
    process_map: HashMap<DWORD, (HANDLE, PathBuf)>,
    /// A set of started processes.  Used to avoid injecting the dll into
    /// the same process twice.
    started: HashSet<HANDLE>,
}

impl Injector {
    /// Create injector with some default parameters
    fn new() -> Self {
        let mut dll_path: Vec<u16>;

        println!("cwd: {:?}", env::current_dir());

        let output;

        // assume injectee.dll is near currently running executable
        if let Ok(mut path) = env::current_exe() {
            path.pop();
            path.push("injectee.dll");
            println!("library path: {:?}", path);
            dll_path = path.as_os_str().encode_wide().collect();
            dll_path.push(0);

            // put an injector log file nearby.
            path.pop();
            path.push("injector.log");
            output = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("could not open log");
        } else {
            panic!("could not get current exe path!");
        }

        Injector {
            run_mode: RunMode::DebugAll,
            dll_path,
            output,
            process_map: HashMap::new(),
            started: HashSet::new(),
        }
    }

    /// Main function
    unsafe fn main(&mut self) {
        let argv: Vec<OsString> = args_os().collect();
        if argv.len() <= 1 {
            println!("no arguments :(");
            return;
        }

        let mut path: Vec<u16> = argv[1].encode_wide().collect();
        path.push(0);

        // Concatenate arguments to create command line
        // TODO: this does not handle quotes/spaces,
        // but that doesn't seem to be necessary so far
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

        // Try SSLKEYLOGFILE env var, like a feature we're trying to mimick
        // The injectee DLL will read this env var
        if let Some(path) = env::var_os("SSLKEYLOGFILE") {
            println!("passing through SSLKEYLOGFILE={:?}", path);
        } else {
            // That was not provided, use the directory of the executable
            if let Ok(mut path) = env::current_exe() {
                path.pop();
                path.push("ssl_keylog.txt");
                println!("putting keylog near currently running binary={:?}", path);
                env::set_var("SSLKEYLOGFILE", path);
            } else {
                println!("could not get SSLKEYLOGFILE and current program path?..");
            }
        }


        let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;

        let start_mode = match self.run_mode {
            RunMode::Debug => DEBUG_ONLY_THIS_PROCESS,
            RunMode::DebugAll => DEBUG_PROCESS,
            RunMode::Suspend => CREATE_SUSPENDED,
        };

        // Create a suspended or debugged process
        let result = CreateProcessW(
            path.as_mut_ptr(),
            args.as_mut_ptr(),
            null_mut::<SECURITY_ATTRIBUTES>(),
            null_mut::<SECURITY_ATTRIBUTES>(),
            0,
            start_mode,
            null_mut(),
            null_mut(),
            &mut startup_info as *mut STARTUPINFOW,
            &mut proc_info as *mut PROCESS_INFORMATION);
        assert!(result != 0, "CreateProcessW failed!");

        // If we started the process in debug mode, the recently
        // created thread won't run, so ignore this code for now
        // let result = WaitForSingleObject(thread_handle, INFINITE);
        // println!("WaitForSingleObject result = {}", result);

        // Finally, resume the process, depending on how we started it
        match self.run_mode {
            RunMode::Debug | RunMode::DebugAll => {
                self.debug_loop(proc_info.dwProcessId);
            }
            RunMode::Suspend => {
                inject_snoop_dll(proc_info.hProcess, &self.dll_path);
                let result = ResumeThread(proc_info.hThread);
                assert!(result != 0, "ResumeThread failed");

                // After everything is done, wait for the project to die.
                // TODO: pass events so that the service can be stopped normally.
                let result = WaitForSingleObject(proc_info.hProcess, INFINITE);
                println!("WaitForSingleObject result = {}", result);
            }
        }

    }

    /// This function will run when a debuggee process has started.
    unsafe fn on_create_process(&mut self, pid: DWORD, process_info: &CREATE_PROCESS_DEBUG_INFO) {
        let process = process_info.hProcess;
        let name = path_for_handle(process_info.hFile);
        writeln!(self.output, "child process created: {:?}", name).unwrap();
        // Add a pid -> (handle, name) map
        self.process_map.insert(pid, (process, name));
    }

    /// This function will run right after the process has loaded all DLLs
    /// and before it exits ntdll!LdrpDoDebuggerBreak
    unsafe fn on_process_loaded(&mut self, process: HANDLE, path: &Path) {
        writeln!(self.output, "process started: {:?}", path).unwrap();
        // only inject the DLL into whitelisted processes
        let targets = [
            //"OculusClient.exe",
            "OVRServer_x64.exe",
            "oculus-platform-runtime.exe",
            "OculusDash.exe",
        ];

        if targets.iter().any(|target| path.ends_with(target)) {
            writeln!(self.output, "injecting the dll!").unwrap();
            inject_snoop_dll(process, &self.dll_path);
        }
    }

    /// This function will run when a breakpoint is encountered
    unsafe fn on_breakpoint(&mut self, pid: DWORD) {
        let (handle, path) = self.process_map[&pid].clone();
        // When we first encounter a breakpoint and we started the process with
        // DEBUG_PROCESS flag, it means that the executable has successfully
        // loaded all modules.  The first breakpoint is located in
        // ntdll!LdrpDoDebuggerBreak.
        if self.started.insert(handle) {
            self.on_process_loaded(handle, &path);
        }
    }

    /// This is main debugger loop.  Process debug events and handle them appropriately.
    /// modelled after https://docs.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop
    unsafe fn debug_loop(&mut self, process_id: DWORD) {
        let mut continue_status = DBG_CONTINUE;
        let mut debug_event = std::mem::zeroed::<DEBUG_EVENT>();
        let debug_event = &mut debug_event;
        while WaitForDebugEvent(debug_event, INFINITE) != 0 {
            writeln!(self.output, "debug event = {}", debug_event.dwDebugEventCode).unwrap();
            match debug_event.dwDebugEventCode {
                EXCEPTION_DEBUG_EVENT => {
                    // Process the exception code. When handling
                    // exceptions, remember to set the continuation
                    // status parameter (dwContinueStatus). This value
                    // is used by the ContinueDebugEvent function.
                    let exception_info = &debug_event.u.Exception.ExceptionRecord;
                    writeln!(self.output, "first chance: {}", debug_event.u.Exception.dwFirstChance).unwrap();
                    writeln!(self.output, "code: 0x{:x?}", exception_info.ExceptionCode as u32).unwrap();
                    writeln!(self.output, "exception: {:?}", exception_info).unwrap();
                    let process = self.process_map[&debug_event.dwProcessId].0;
                    dump_memory(&mut self.output, process, exception_info.ExceptionAddress, 256);

                    continue_status = match exception_info.ExceptionCode {
                        EXCEPTION_ACCESS_VIOLATION => {
                            // First chance: Pass this on to the system.
                            // Last chance: Display an appropriate error.
                            DBG_EXCEPTION_NOT_HANDLED
                        }
                        EXCEPTION_BREAKPOINT => {
                            // First chance: Display the current
                            // instruction and register values.
                            self.on_breakpoint(debug_event.dwProcessId);
                            DBG_CONTINUE
                        }
                        EXCEPTION_DATATYPE_MISALIGNMENT => {
                            // First chance: Pass this on to the system.
                            // Last chance: Display an appropriate error.
                            DBG_CONTINUE
                        }
                        EXCEPTION_SINGLE_STEP => {
                            // First chance: Update the display of the
                            // current instruction and register values.
                            DBG_CONTINUE
                        }
                        DBG_CONTROL_C => {
                            // First chance: Pass this on to the system.
                            // Last chance: Display an appropriate error.
                            DBG_EXCEPTION_NOT_HANDLED
                        }
                        _ => {
                            // Handle other exceptions.
                            DBG_EXCEPTION_NOT_HANDLED
                        }
                    };
                    // continue_status = DBG_EXCEPTION_NOT_HANDLED;
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    // As needed, examine or change the thread's registers
                    // with the GetThreadContext and SetThreadContext functions;
                    // and suspend and resume thread execution with the
                    // SuspendThread and ResumeThread functions.

                    // continue_status = OnCreateThreadDebugEvent(debug_event);
                }
                CREATE_PROCESS_DEBUG_EVENT => {
                    // As needed, examine or change the registers of the
                    // process's initial thread with the GetThreadContext and
                    // SetThreadContext functions; read from and write to the
                    // process's virtual memory with the ReadProcessMemory and
                    // WriteProcessMemory functions; and suspend and resume
                    // thread execution with the SuspendThread and ResumeThread
                    // functions. Be sure to close the handle to the process image
                    // file with CloseHandle.
                    self.on_create_process(debug_event.dwProcessId, &debug_event.u.CreateProcessInfo);

                    // continue_status = OnCreateProcessDebugEvent(debug_event);
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    // Display the thread's exit code.
                    // continue_status = OnExitThreadDebugEvent(debug_event);
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    // Delete the mapping, since we no longer work on this process
                    if let Some((handle, _file)) = self.process_map.remove(&debug_event.dwProcessId) {
                        CloseHandle(handle);
                    }
                    if debug_event.dwProcessId == process_id {
                        writeln!(self.output, "our child process has succesfully died! code={}",
                                 debug_event.u.ExitProcess.dwExitCode).unwrap();
                        // we're done!
                        break;
                    }
                }
                LOAD_DLL_DEBUG_EVENT => {
                    // Read the debugging information included in the newly
                    // loaded DLL. Be sure to close the handle to the loaded DLL
                    // with CloseHandle.

                    // continue_status = OnLoadDllDebugEvent(debug_event);
                }

                UNLOAD_DLL_DEBUG_EVENT => {
                    // Display a message that the DLL has been unloaded.
                    // continue_status = OnUnloadDllDebugEvent(debug_event);
                }

                OUTPUT_DEBUG_STRING_EVENT => {
                    // Display the output debugging string.
                    // continue_status = OnOutputDebugStringEvent(debug_event);
                }
                RIP_EVENT => {
                    // continue_status = OnRipEvent(debug_event);
                }
                _ => {
                    // unknown debug event?
                }
            }
            ContinueDebugEvent(debug_event.dwProcessId,
                               debug_event.dwThreadId,
                               continue_status);
        }
        writeln!(self.output, "end of the line?").unwrap();
    }
}

fn main() {
    let mut runner = Injector::new();
    unsafe { runner.main() }
}
