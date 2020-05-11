#![feature(untagged_unions)]

/// injectee -- this DLL will be injected into OVRServer_x64 process
///
/// It will patch SSL functions in order to extract private keys
use std::cell::RefCell;
use std::collections::{HashSet};
use std::env;
use std::mem::{size_of};
use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStringExt;
use std::ptr::{null_mut};
use std::fs::{File, OpenOptions};
use std::io::{Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

/// winapi module -- describing enough win32api surface to work with
mod winapi;

use winapi::*;

struct PatternFinder<'a> {
    src: &'a[u8],
    pattern: &'a[u8],
    index: usize,
}

impl<'a> PatternFinder<'a> {
    /// Construct a new pattern finder for given pattern and source
    fn new<'b>(pattern: &'b[u8], src: &'b[u8]) -> PatternFinder<'b> {
        PatternFinder {
            src,
            pattern,
            index: 0
        }
    }
}

impl<'a> Iterator for PatternFinder<'a> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        let pattern_length = self.pattern.len();
        let src_length = self.src.len();
        while self.index + pattern_length <= src_length {
            let slice = &self.src[self.index..];
            self.index += 1;
            if slice.starts_with(self.pattern) {
                return Some(self.index - 1);
            }
        }
        None
    }
}

struct ModuleRegions {
    ptr: *const c_void,
    size: usize,
    offset: usize,
}

impl ModuleRegions {
    fn new(module_info: &MODULEINFO) -> Self {
        ModuleRegions {
            ptr: module_info.lpBaseOfDll,
            size: module_info.SizeOfImage as usize,
            offset: 0,
        }
    }
}

impl Iterator for ModuleRegions {
    type Item = MEMORY_BASIC_INFORMATION;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.size {
            return None;
        }
        const INFO_SIZE: usize = size_of::<MEMORY_BASIC_INFORMATION>();
        unsafe {
            let mut info = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            let size = VirtualQuery(self.ptr as *mut c_void, &mut info, INFO_SIZE);
            // whoa, let's stop iterating if the request fails or we're out of region
            if size != INFO_SIZE || info.AllocationProtect == 0 {
                return None;
            }
            self.offset += info.RegionSize;
            self.ptr = (self.ptr as *const u8).add(info.RegionSize) as *const c_void;
            Some(info)
        }
    }
}

/// Patch -- describes a change made to in-memory program code
///
/// This allows us to overwrite in-memory code of the running process
/// to insert ourselves so we can snoop on the data.
struct Patch {
    /// Human-readable name of the patch.
    /// Currently maps to SSL function we patch.
    name: &'static str,
    /// What address we should call with ssl_state pointer
    call_addr: *mut c_void,
    /// Pattern to look for
    pattern: &'static[u8],
    /// Offset from pattern
    pattern_offset: usize,
    /// Location of call address in the "replacement" code
    addr_offset: usize,
    /// What code is expected at the specified location.
    /// This allows us to check if the binary has been updated.
    /// We don't want to blindly overwrite random code.
    expect: &'static[u8],
    /// What code we should write in.
    replacement: &'static[u8],
}

/// Describes possible failures we could encounter when patching
#[derive(Debug)]
enum PatchError {
    /// Patch didn't find the location to apply to
    PatternNotFound,
    /// Patch location is out of range of the DLL address space
    OutOfRange,
    /// Code at the specified location did not match expectation.
    /// Probably means an unsupported version of the DLL
    CodeMismatch,
    /// There's not enough 0xcc padding after the function end to patch this function
    NotEnoughSpace,
    /// Could not set memory protection to Read+Write
    VirtualUnProtect,
    /// Could not set memory protection to Read+Execute
    VirtualReProtect,
}

impl Patch {
    /// Apply a patch to a module described by `module_info`.
    ///
    /// Returns either location of change or error occured during patch.
    /// This function will try to apply patch on multiple location
    /// and return first success or last error.
    /// # Safety
    /// This is inherently unsafe because we're patching program memory
    pub unsafe fn apply(&self, module_info: &MODULEINFO) -> Result<isize, PatchError> {
        let mut rv = Err(PatchError::PatternNotFound);

        let possible_locations = ModuleRegions::new(module_info)
            // only grab executable regions
            .filter(|region| region.Protect & PAGE_EXECUTE_READ != 0)
            .flat_map(|region| {
                let memory_slice = std::slice::from_raw_parts(
                        region.BaseAddress as *const u8, region.RegionSize);
                // find the requested pattern in a given region
                PatternFinder::new(self.pattern, memory_slice)
                    .map(move |location| (region.BaseAddress, region.RegionSize, location))
            })
            // collect locations into a Vec because if we iterate,
            // we may invalidate the slice by patching the memory
            .collect::<Vec<(*mut c_void, usize, usize)>>();

        for (base_ptr, size, location) in possible_locations {
            let location = (location + self.pattern_offset) as isize;

            let maxlen = self.replacement.len().max(self.expect.len());
            if size < location as usize + maxlen {
                rv = Err(PatchError::OutOfRange);
                continue;
            }

            // write in call address at addr_offset in the patch
            let mut patch = self.replacement.to_vec();
            patch[self.addr_offset..self.addr_offset + size_of::<usize>()]
                .clone_from_slice(&(self.call_addr as usize).to_ne_bytes());

            let target_ptr = (base_ptr as *mut u8).offset(location);
            let target_slice = std::slice::from_raw_parts_mut(target_ptr, maxlen);

            if &target_slice[..self.expect.len()] != self.expect {
                rv = Err(PatchError::CodeMismatch);
                continue;
            }

            // if the replacement is bigger than the pattern, check if the last instruction
            // in target slice is int3 (byte 0xcc), meaning we can fit into the padding
            if self.expect.len() < self.expect.len() && target_slice.last() != Some(&0xcc) {
                return Err(PatchError::NotEnoughSpace);
            }

            // VirtualProtect requires us to pass a pointer to flOldProtect
            let mut before = 0;
            // Set memory protection to Read+Write
            let result = VirtualProtect(target_ptr as _, patch.len(), PAGE_READWRITE, &mut before as _);
            if result == 0 {
                return Err(PatchError::VirtualUnProtect);
            }

            // Actually apply the patch
            target_slice[..patch.len()].clone_from_slice(&patch);
            // Set memory protection to Read+Execute
            let result = VirtualProtect(target_ptr as _, patch.len(), PAGE_EXECUTE_READ, &mut before as _);
            if result == 0 {
                return Err(PatchError::VirtualReProtect);
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
        pattern: &[
            0x48, 0x8b, 0x41, 0x08, // MOV RAX,qword ptr [RCX + 0x8]
            0xc7, 0x41, 0x48,       // MOV dword ptr [RCX + 0x48],0x5000
            0x00, 0x50, 0x00, 0x00, //
            0x48, 0x89, 0x7c,       // MOV qword ptr [RSP + 0x30],RDI
            0x24, 0x30,
            0x33, 0xff,             // XOR EDI,EDI
            0x89, 0x79, 0x38,       // MOV dword ptr [RCX + 0x38],EDI
            0x89, 0x79, 0x44,       // MOV dword ptr [RCX + 0x44],EDI
        ],
        pattern_offset: 0x61,
        // expect to have: 5b 48 ff 60 28: POP RBX; REX.W JMP qword ptr [RAX + 0x28]
        expect: &[0x48, 0x83, 0xc4, 0x20, 0x5b, 0x48, 0xff, 0x60, 0x28],
        // mov  rax, 0x1337133713371337
        // call rax
        // add  rsp, 20
        // pop  rbx
        // ret
        addr_offset: 2,
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
        pattern: &[
            0x48, 0x8b, 0x41, 0x08, // MOV RAX,qword ptr [RCX + 0x8]
            0x33, 0xff,             // XOR EDI,EDI
            0x89, 0x79, 0x38,       // MOV dword ptr [RCX + 0x38],EDI
            0x48, 0x8b, 0xd9,       // MOV RBX,RCX
            0x89, 0x79, 0x44,       // MOV dword ptr [RCX + 0x44],EDI
            0xc7, 0x41, 0x48,       // MOV dword ptr [RCX + 0x48],0x5000
            0x00, 0x50, 0x00, 0x00,

        ],
        pattern_offset: 0x4c,
        // expect to have: 48 8b 5c 24 30: MOV RBX,qword ptr [RSP + 0x30]
        expect: &[
            0x48, 0x89, 0xbb, 0xf0, 0x00, 0x00, 0x00,
            0x48, 0x8b, 0x5c, 0x24, 0x30,
            0x48, 0x83, 0xc4, 0x20,
            0x5f,
            0xc3,
        ],
        // mov  rcx, rbx
        // mov  rax, 0x1337133713371337
        // call rax
        // mov  rbx, qword ptr [rsp+0x30]
        // add  rsp, 0x20
        // pop  rdi
        // ret
        addr_offset: 13,
        replacement: &[
            0x48, 0x89, 0xbb, 0xf0, 0x00, 0x00, 0x00, // mov qword ptr [0xf0 + rbx], rdi
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

// A type definition for a sender that sends private keys
type PkSender = Sender<(Vec<u8>, Vec<u8>)>;

// This sender will be used by all threads to clone their own senders from.
// We don't control when threads start or what they're data is going to be.
static mut SENDER: Option<PkSender> = None;

thread_local! {
    // ... each thread is going to store its own sender in ThreadLocalStorage
    // cloned from the global SENDER
    static LOCAL_SENDER: RefCell<Option<PkSender>> =
        RefCell::new(unsafe { SENDER.clone() });
}

/// PkData -- struct used to pass private key data from `ssl_inspector`
/// The matching struct in `ssl_inspector` is `private_keys`.
#[repr(C)]
struct PkData {
    client_random: *mut u8,
    client_random_size: usize,
    master_key: *mut u8,
    master_key_size: usize,
}

/// Pointer to ssl->method->ssl_connect
type SslConnectFn = extern "C" fn(*mut c_void) -> i32;

extern "C" {
    fn ssl_read_pk_data(raw: *mut c_void, pk_data: *mut PkData);
    fn ssl_get_ssl_connect(raw: *mut c_void) -> SslConnectFn;
}

/// There is too little space after SSL_connect function.
/// One solution is to move part of that function here.
/// We patch out ssl->method->ssl_connect() and do it here
#[no_mangle]
unsafe fn ssl_connect_and_peek(raw: *mut c_void) -> i32 {
    let rv = ssl_get_ssl_connect(raw)(raw);
    peek_ssl_keys(raw);
    rv
}

/// Extract private keys using pointer to ssl_state struct and
/// send them to the writer thread.
#[no_mangle]
unsafe fn peek_ssl_keys(raw: *mut c_void) {
    let keys = {
        let mut pk_data = std::mem::zeroed();
        ssl_read_pk_data(raw, &mut pk_data);
        let client_random = std::slice::from_raw_parts(
            pk_data.client_random, pk_data.client_random_size);
        let master_key = std::slice::from_raw_parts(
            pk_data.master_key, pk_data.master_key_size);

        (
            client_random.to_vec(),
            master_key.to_vec()
        )
    };

    LOCAL_SENDER.with(|s| {
        if let Some(sender) = s.borrow_mut().as_ref() {
            let _ = sender.send(keys);
        } else {
            // This shouldn't happen and we don't really want to panic
            println!("Snaaaaake!");
        }
    });
}

/// Write hex dump of source bytes to target Vec
fn dump_hex(source: &[u8], target: &mut Vec<u8>) {
    const HEX: &[u8] = b"0123456789abcdef";
    for &chr in source {
        target.push(HEX[(chr >> 4) as usize]);
        target.push(HEX[(chr & 0xf) as usize]);
    }
}

/// key writing thread
/// This will recive messages from multiple threads over rx channel.
/// And write them to the log file.
fn key_writer(receiver: Receiver<(Vec<u8>, Vec<u8>)>, mut file: File) {
    let mut set = HashSet::new();

    while let Ok((client_random, master_key)) = receiver.recv() {
        // zero client_random means it was not initialized yet
        if client_random.iter().all(|&c| c == 0) {
            file.write_all(b"ZERO_CLIENT_RANDOM\n").unwrap();
            continue;
        }
        // similar situation with master key
        if master_key.is_empty() {
            file.write_all(b"EMPTY_MASTER_KEY\n").unwrap();
            continue;
        }

        let mut line = b"CLIENT_RANDOM ".to_vec();

        line.reserve(client_random.len() + master_key.len() + 2);
        dump_hex(&client_random, &mut line);
        line.push(b' ');
        dump_hex(&master_key, &mut line);
        line.push(b'\n');

        // let's not print duplicates
        if !set.contains(&line) {
            file.write_all(&line).unwrap();
            set.insert(line);
        }
    }
}

fn get_exec_name() -> OsString {
    let mut buf = vec![0u16; 1024];
    let written = unsafe {
        GetModuleFileNameW(null_mut(), buf.as_mut_ptr(), buf.len() as i32)
    };
    assert!((written as usize) < buf.len(), "whoa, file name is too long?");
    OsString::from_wide(&buf[0..(written as usize)])
}

/// initialize will open ssl keylog file, apply patches,
/// create global SENDER and start the key writer thread.
unsafe fn initialize() {
    // decide keylog path depending on env
    let path =
        if let Some(ssl_keylog) = env::var_os("SSLKEYLOGFILE") {
            PathBuf::from(ssl_keylog)
        } else {
            // ... or use temp dir
            let mut temp = env::temp_dir();
            temp.push("ssl_keylog.txt");
            temp
        };
    println!("SSLKEYLOGFILE={:?}", path);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("could not open ssllog");

    let (tx, rx) = channel();
    SENDER = Some(tx);

    // mapping between executable name and module that needs to be patched
    const MODULE_FOR_EXEC: &[(&str, &[u8])] = &[
        ("OVRServer_x64.exe", b"OculusAppFramework.dll\0"),
        ("oculus-platform-runtime.exe", b"oculus-platform-runtime.exe\0"),
        ("OculusDash.exe", b"OculusDash.exe\0"),
    ];

    let exec_name = get_exec_name();
    let exec_path = Path::new(&exec_name);
    file.write_all(format!("exec path = {:?}\n", exec_path).as_bytes())
        .unwrap();
    let module_name = MODULE_FOR_EXEC.iter()
        .find_map(|(file, module)| {
            if exec_path.ends_with(file) {
                Some(module)
            } else {
                None
            }
        });

    let module_name = if let Some(name) = module_name {
        name
    } else {
        file.write_all(format!("whoa, can't find appropriate module name for {:?}\n", exec_path).as_bytes())
            .unwrap();
        return;
    };
    let utf_mod = std::str::from_utf8(module_name).unwrap().trim_matches('\0');
    file.write_all(format!("module name = {:?}\n", utf_mod).as_bytes())
        .unwrap();

    let proc = GetCurrentProcess();
    let handle = GetModuleHandleA(module_name.as_ptr() as _);
    let mut module_info: MODULEINFO = std::mem::zeroed();
    let result = K32GetModuleInformation(
        proc, handle, &mut module_info, size_of::<MODULEINFO>() as DWORD);
    assert!(result != 0);

    file.write_all(format!("going to patch {} locations\n", PATCHES.len()).as_bytes()).unwrap();
    for patch in PATCHES {
        match patch.apply(&module_info) {
            Ok(addr) => file.write_all(
                format!("{:?} patched: {} at 0x{:x}\n", utf_mod, patch.name, addr).as_bytes()).unwrap(),
            Err(ee) => file.write_all(
                format!("{:?} cannot patch: {} {:?}\n", utf_mod, patch.name, ee).as_bytes()).unwrap(),
        }
    }

    thread::spawn(move || key_writer(rx, file));
}

/// Entry point for the DLL
#[no_mangle]
#[allow(non_snake_case)]
pub fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    _lp_reserved: LPVOID
    ) -> BOOL
{
    // This function can be called on many occasions.
    // We only want to do initialization on DLL load.
    if fdw_reason == DLL_PROCESS_ATTACH {
        unsafe { initialize() };
    }
    1
}
