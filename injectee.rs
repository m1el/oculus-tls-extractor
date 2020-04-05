use std::ffi::{c_void};
use std::collections::{HashSet};
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{Write};
use std::thread;
use std::sync::mpsc::{Receiver, Sender, channel};

#[allow(dead_code)]
#[allow(non_snake_case)]
mod winapi {
    use std::ffi::{c_void};
    pub type BOOL = i32;
    pub type DWORD = i32;
    pub type HINSTANCE = *mut c_void;
    pub type HANDLE = *mut c_void;
    pub type LPVOID = *mut c_void;
    pub type LPSTR = *mut u8;

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
}

use winapi::*;

struct Patch {
    name: &'static str,
    call_addr: *mut c_void,
    locations: &'static[isize],
    addr_offset: usize,
    expect: &'static[u8],
    replacement: &'static[u8],
}

#[derive(Debug)]
enum PatchError {
    NoLocationsSpecified,
    OutOfRange,
    CodeMismatch,
    VirtualUnProtect,
    VirtualReProtect,
}

impl Patch {
    pub fn apply(&self, module_info: &MODULEINFO) -> Result<isize, PatchError> {
        let mut rv = Err(PatchError::NoLocationsSpecified);
        for &location in self.locations {
            let maxlen = self.replacement.len().max(self.expect.len());
            if (module_info.SizeOfImage as usize) < location as usize + maxlen {
                rv = Err(PatchError::OutOfRange);
                continue;
            }

            let mut patch = self.replacement.to_vec();
            patch[self.addr_offset..self.addr_offset + std::mem::size_of::<usize>()]
                .clone_from_slice(&(self.call_addr as usize).to_ne_bytes());

            unsafe {
                let target_ptr = (module_info.lpBaseOfDll as *mut u8).offset(location);
                let target_slice = std::slice::from_raw_parts_mut(target_ptr, maxlen);
                if &target_slice[..self.expect.len()] != self.expect {
                    rv = Err(PatchError::CodeMismatch);
                    continue;
                }

                let mut before = 0;
                let result = VirtualProtect(target_ptr as _, patch.len(), PAGE_READWRITE, &mut before as _);
                if result == 0 {
                    return Err(PatchError::VirtualUnProtect);
                }
                target_slice[..patch.len()].clone_from_slice(&patch);
                let result = VirtualProtect(target_ptr as _, patch.len(), PAGE_EXECUTE_READ, &mut before as _);
                if result == 0 {
                    return Err(PatchError::VirtualReProtect);
                }
            }

            return Ok(location);
        }
        rv
    }
}

const PATCHES: &[Patch] = &[
    Patch {
        name: "SSL_connect",
        call_addr: ssl_connect_and_peek as _,
        locations: &[0x74322a, 0x7494ba], // newer first
        addr_offset: 2,
        // expect to have: 5b 48 ff 60 28: POP RBX; REX.W JMP qword ptr [RAX + 0x28]
        expect: &[0x48, 0x83, 0xc4, 0x20, 0x5b, 0x48, 0xff, 0x60, 0x28],
        // mov  rax, 0x1337133713371337
        // call rax
        // add  rsp, 20
        // pop  rbx
        // ret
        replacement: &[
            0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, ptr
            0xff, 0xd0,             // call   rax
            0x48, 0x83, 0xc4, 0x20, // add rsp, 20
            0x5b,                   // pop rbx
            0xc3,                   // ret
        ]
    },

    Patch {
        name: "SSL_set_connect_state",
        call_addr: peek_ssl_keys as _,
        locations: &[0x743df6, 0x74a086], // newer first
        addr_offset: 5,
        // expect to have: 48 8b 5c 24 30: MOV RBX,qword ptr [RSP + 0x30]
        expect: &[0x48, 0x8b, 0x5c, 0x24, 0x30],
        // mov  rcx, rbx
        // mov  rax, 0x1337133713371337
        // call rax
        // mov  rbx, qword ptr [rsp+0x30]
        // add  rsp, 0x20
        // pop  rdi
        // ret
        replacement: &[
            0x48, 0x89, 0xd9,             // mov    rcx,rbx
            0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, ptr
            0xff, 0xd0,                   // call rax
            0x48, 0x8b, 0x5c, 0x24, 0x30, // mov  rbx,qword ptr [rsp+0x30]
            0x48, 0x83, 0xc4, 0x20,       // add  rsp,0x20
            0x5f,                         // pop  rdi
            0xc3,                         // ret
        ]
    },
];

#[repr(C)]
struct PkData {
    client_random: *mut u8,
    client_random_size: usize,
    master_key: *mut u8,
    master_key_size: usize,
}

type SslConnectFn = extern "C" fn(*mut c_void) -> i32;

extern "C" {
    fn ssl_read_pk_data(raw: *mut c_void, pk_data: *mut PkData);
    fn ssl_get_ssl_connect(raw: *mut c_void) -> SslConnectFn;
}

static mut SENDER: Option<Sender<(Vec<u8>, Vec<u8>)>> = None;

#[no_mangle]
pub unsafe fn ssl_connect_and_peek(raw: *mut c_void) -> i32 {
    let rv = ssl_get_ssl_connect(raw)(raw);
    peek_ssl_keys(raw);
    rv
}

#[no_mangle]
pub fn peek_ssl_keys(raw: *mut c_void) {
    let keys = unsafe {
        let mut pk_data = std::mem::zeroed();
        ssl_read_pk_data(raw, &mut pk_data);
        let client_random = std::slice::from_raw_parts(pk_data.client_random, pk_data.client_random_size);
        let master_key = std::slice::from_raw_parts(pk_data.master_key, pk_data.master_key_size);
        (
            client_random.to_vec(),
            master_key.to_vec()
        )
    };

    thread_local! {
        static LOCAL_SENDER: RefCell<Option<Sender<(Vec<u8>, Vec<u8>)>>> = RefCell::new(unsafe { SENDER.clone() });
    }

    LOCAL_SENDER.with(|s| {
        if let Some(sender) = s.borrow_mut().as_ref() {
            let _ = sender.send(keys);
        } else {
            // getting events before getting initialized?
        }
    });
}

fn hex_char(byte: u8) -> u8 {
    b"0123456789abcdef"[(byte & 0xf) as usize]
}

#[no_mangle]
pub fn key_writer(receiver: Receiver<(Vec<u8>, Vec<u8>)>, mut file: File) {
    let mut set = HashSet::new();

    while let Ok((client_random, master_key)) = receiver.recv() {
        if client_random.iter().all(|&c| c == 0) {
            file.write_all(b"ZERO_CLIENT_RANDOM\n").unwrap();
            continue;
        }
        if master_key.is_empty() {
            file.write_all(b"EMPTY_MASTER_KEY\n").unwrap();
            continue;
        }

        let mut line = b"CLIENT_RANDOM ".to_vec();
        for byte in client_random {
            line.push(hex_char(byte >> 4));
            line.push(hex_char(byte >> 0));
        }
        line.push(b' ');

        for byte in master_key {
            line.push(hex_char(byte >> 4));
            line.push(hex_char(byte >> 0));
        }
        line.push(b'\n');

        if !set.contains(&line) {
            file.write_all(&line).unwrap();
            set.insert(line);
        }
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lp_reserved: LPVOID
    ) -> BOOL
{
    if fdw_reason == DLL_PROCESS_ATTACH {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("g:\\projects\\wrap\\keylog.txt")
            .unwrap();

        let (tx, rx) = channel();
        let proc = GetCurrentProcess();
        let handle = GetModuleHandleA(b"OculusAppFramework.dll\0".as_ptr() as _);
        let mut module_info: MODULEINFO = std::mem::zeroed();
        let result = K32GetModuleInformation(proc, handle, &mut module_info, std::mem::size_of::<MODULEINFO>() as DWORD);
        assert!(result != 0);

        for patch in PATCHES {
            match patch.apply(&module_info) {
                Ok(addr) => write!(file, "patched: {} at 0x{:x}\n", patch.name, addr).unwrap(),
                Err(ee) => write!(file, "cannot patch: {} {:?}\n", patch.name, ee).unwrap(),
            }
        }

        SENDER = Some(tx);

        thread::spawn(move || key_writer(rx, file));
    }
    1
}
