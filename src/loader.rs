
use crate::win::*;
use libc::*;
use std::fs;
use std::error::Error;

pub struct ProcessInfo {
    h_thread: HANDLE,
    h_proc: LPCVOID,
    vmem: LPVOID,
}

impl ProcessInfo {
    fn new(h_thread: HANDLE, h_proc: LPCVOID, vmem: LPVOID) -> Self {
        ProcessInfo {
            h_thread: h_thread,
            h_proc: h_proc,
            vmem: vmem,
        }
    }
}

pub fn dll_attach(path_to_dll: String, pid: u32) -> Result<ProcessInfo, Box<dyn Error>> {
    if !fs::metadata(path_to_dll.clone()).is_ok() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound, format!("File not found: {}", path_to_dll)
        )));
    }
    unsafe {
        let h_proc = OpenProcess(ProcessAccessRight::PROCESS_ALL_ACCESS as DWORD, 0, pid);
        let vmem = VirtualAllocEx(
            h_proc, std::ptr::null(), path_to_dll.toWchars().sizeOfString() as u32, 
            VirtualMemory::MEM_COMMIT as u32, MemoryProtect::PAGE_READWRITE as u32);
        let status = WriteProcessMemory(
            h_proc, vmem, 
            path_to_dll.toWchars().as_ptr() as *const c_void, 
            path_to_dll.toWchars().sizeOfString() as u32, 
            std::ptr::null_mut());
        if status == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Write process memory failed, PID-{}", pid)
            )));
        }
        // CreateRemoteThread 
        let kernel32 = LoadLibraryW("kernel32.dll\0".toWchars().as_ptr());
        let load_library_w = GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr());
        let mut thread_id: u32 = 0;
        let h_thread = CreateRemoteThread(
            h_proc, std::ptr::null_mut(), 0, load_library_w, vmem, 0, &mut thread_id);
        println!("success");
        FreeLibrary(kernel32);
        Ok(ProcessInfo::new(h_thread, h_proc, vmem))
    }
}

// wait until dll attached, after detah
#[allow(unused_must_use)]
pub fn dll_detach_wait(process: ProcessInfo) -> Result<(), Box<dyn Error>> {
    unsafe {
        if process.h_thread != std::ptr::null() {
            WaitForSingleObject(process.h_thread, INFINITE);
        }
        dll_detach(process);
    }
    return Ok(());
}

fn dll_detach(process: ProcessInfo)->Result<(), Box<dyn Error>> {
    unsafe {
        if VirtaulFreeEx(process.h_proc, process.vmem, 0, VirtualMemory::MEM_RELEASE as u32) == 0 {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "")));
        }
        CloseHandle(process.h_proc);
    }
    return Ok(())
}
