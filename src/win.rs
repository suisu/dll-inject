use std::mem;
use core::ffi::c_void;

// win types to rust
#[allow(unused_must_use)]
pub type LPCVOID = *const c_void;
pub type LPVOID = *mut c_void;
pub type HANDLE = LPCVOID;
pub type HMODULE = LPCVOID;
pub type UINT = i32;
pub type DWORD = u32;
pub type BOOL = i32;
pub type LPDWORD = *mut DWORD;
pub type WSTR = Vec<u16>;
pub type LPWSTR = *mut u16;
pub type LPCWSTR = *const u16;
pub type LPCSTR = *const u8;
#[allow(non_camel_case_types)]
pub type LPSECURITY_ATTRIBUTES = *mut SECURITY_ATTRIBUTES;
#[allow(non_camel_case_types)]
pub type LPTHREAD_START_ROUTINE = fn(lpThreadParameter:LPCVOID);
pub const INFINITE:u32=0xFFFFFFFF;


#[repr(C)]
/*
typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
*/
#[allow(non_snake_case)]
pub struct SECURITY_ATTRIBUTES {
    nLength:DWORD,
    lpSecurityDescriptor:LPVOID,
    bInheritHandle:BOOL,
}
// https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
#[allow(non_camel_case_types)]
pub enum MemoryProtect {
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_WRITECOPY = 0x08,
    PAGE_TARGETS_INVALID = 0x40000000,
    PAGE_GUARD = 0x100, 
    PAGE_NOCACHE = 0x200,
    PAGE_WRITECOMBINE = 0x400,
}

// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
#[allow(non_camel_case_types)]
pub enum VirtualMemory {
    MEM_COMMIT = 0x00001000,
    MEM_RESERVE = 0x00002000,
    MEM_RESET = 0x00080000,
    MEM_RESET_UNDO = 0x1000000,
    MEM_LARGE_PAGES = 0x20000000,
    MEM_PHYSICAL = 0x00400000,
    MEM_TOP_DOWN = 0x00100000,
    MEM_WRITE_WATCH = 0x00200000,
    MEM_DECOMMIT = 0x00004000,
    MEM_RELEASE = 0x00008000,
}

// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
#[allow(non_camel_case_types)]
pub enum ProcessAccessRight {
    PROCESS_ALL_ACCESS = 0x001F0FFF,
    PROCESS_CREATE_PROCESS = 0x0080,
    PROCESS_CREATE_THREAD = 0x0002,
    PROCESS_DUP_HANDLE = 0x0040,
    PROCESS_QUERY_INFORMATION = 0x0400,
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
    PROCESS_SET_INFORMATION = 0x0200,
    PROCESS_SET_QUOTA = 0x0100,
    PROCESS_SUSPEND_RESUME = 0x0800,
    PROCESS_TERMINATE = 0x0001,
    PROCESS_VM_OPERATION = 0x0008,
    PROCESS_VM_READ = 0x0010,
    PROCESS_VM_WRITE = 0x0020,
    SYNCHRONIZE = 0x00100000,
}

// windows APIs - https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-functions
#[link(name = "kernel32")]
#[allow(non_snake_case)]
#[allow(improper_ctypes)]
extern "system"{
    pub fn FreeLibrary(hLibModule: HMODULE);
    pub fn LoadLibraryW(lpLibFileNme: LPCWSTR) -> HMODULE;
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) -> LPTHREAD_START_ROUTINE;
    pub fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
    pub fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: LPCVOID, nSize: DWORD, lpNumberOfBytesWritten : LPDWORD) -> BOOL;
    pub fn VirtualAllocEx(hProcess: HANDLE, lpAddress: LPCVOID, dwSize: DWORD, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID;
    pub fn VirtaulFreeEx(hProcess: HANDLE, lpAddress: LPCVOID, dwiSize: DWORD, dwFreeType: DWORD) -> BOOL;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
    pub fn CreateRemoteThread(
        hProcess: HANDLE,
        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
        dwStackSize: DWORD,
        lpStartAddress: LPTHREAD_START_ROUTINE,
        lpParameter: LPVOID,
        dwCreationFlags: DWORD,
        lpThreadId: LPDWORD
    ) -> HANDLE;
}

// specify the length of WCHAR, if an array, the length of an array.
#[allow(non_snake_case)]
pub trait WSTRING {
    fn sizeOfString(&self) -> usize;
}
impl WSTRING for WSTR {
    fn sizeOfString(&self) -> usize {
        mem::size_of::<u16>()*self.len()
    }
}

#[allow(non_snake_case)]
pub trait WindowsString {
    fn fromWcharPtr(&self, ptr: *const u16) -> String;
    fn toWchars(&self) -> WSTR;
}
impl WindowsString for str {
    fn fromWcharPtr(&self, ptr: *const u16) -> String {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        unsafe {
            assert!(!ptr.is_null());
            let len = (0..::std::isize::MAX).position(|i| *ptr.offset(i) == 0).unwrap();
            let slice = ::std::slice::from_raw_parts(ptr, len);
            OsString::from_wide(slice).to_string_lossy().into_owned()
        }
    }
    fn toWchars(&self) -> WSTR {
        use std::iter;
        self.encode_utf16().chain(iter::once(0)) // append a null
        .collect()
        //OsStr::new(self).encode_utf16().chain(Some(0).into_iter()).collect::<Vec<_>>()
    }
}
