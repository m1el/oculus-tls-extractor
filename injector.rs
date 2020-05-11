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
mod winapi;
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
    if !module.is_null() {
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
    assert!(!kernel32_mod.is_null(), "Get Kernel32.dll handle failed?");

    // 1) kernel32.dll has the same address space in all running processes
    let load_library_ptr = GetProcAddress(
        kernel32_mod, b"LoadLibraryW\0".as_ptr() as _);
    assert!(!load_library_ptr.is_null(),
        "Get pointer to LoadLibraryW failed?");

    // All following operations require us to have certain access
    // to the process, but since we started it in debug mode,
    // we probably have that access.
    //
    // 2) Allocate memory for DLL path in the target process
    let name_ptr = VirtualAllocEx(
        process, null_mut(), size_of_slice(dll_path) as _,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    assert!(!name_ptr.is_null(), "VirtualAllocEx failed");

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
    assert!(!thread_handle.is_null(), "CreateRemoteThread failed");
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

        // handle for OVRServiceStopEvent is passed as
        // the first argument to OVRServer_x64.exe
        let stop_service_event = argv.get(2)
            .and_then(|s| s.to_str())
            .and_then(|s| usize::from_str_radix(s, 16).ok());

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
            1,
            start_mode,
            null_mut(),
            null_mut(),
            &mut startup_info as *mut STARTUPINFOW,
            &mut proc_info as *mut PROCESS_INFORMATION);
        assert!(result != 0, "CreateProcessW failed!");

        if let Some(handle) = stop_service_event {
            // If the debug handle is present and we've received
            // service stop event then exit successfully.
            std::thread::spawn(move || {
                WaitForSingleObject(handle as HANDLE, INFINITE);
                std::process::exit(0);
            });
        }

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
        while WaitForDebugEventEx(debug_event, INFINITE) != 0 {
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
