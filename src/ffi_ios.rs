//! C ABI over the ECH proxy core, for the iOS Network Extension.
//!
//! The extension links this static library and calls:
//!   - `linuxdo_proxy_start(config_toml, home_dir)` → opaque handle
//!   - `linuxdo_proxy_stop(handle)`
//!   - `linuxdo_export_ca_der(home_dir, out_len)` → malloc'd DER buffer
//!   - `linuxdo_free_bytes(ptr, len)` to release that buffer
//!
//! All entry points are `#[cfg(target_os = "ios")]`. Everything runs inside the
//! extension process; there is no fork/exec and no system-trust modification.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::thread::JoinHandle;

use tokio::sync::watch;

use crate::certs;
use crate::config::AppConfig;
use crate::paths::AppPaths;
use crate::proxy;

/// Holds the most recent FFI error message so Swift can surface the real cause
/// instead of an opaque null. Set by fallible entry points on failure.
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_last_error(msg: impl Into<String>) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = Some(msg.into());
    }
}

/// Opaque handle returned to Swift. Owns the shutdown channel and the runtime
/// thread. Freed by `linuxdo_proxy_stop`.
pub struct ProxyHandle {
    shutdown_tx: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(|s| s.to_owned())
}

/// Builds config + paths + cert bundle, then spawns a single-threaded tokio
/// runtime running `run_proxy` until shutdown. Returns null on failure.
fn start_inner(
    config_toml: Option<String>,
    home_dir: String,
    provided_certs: Option<(String, String, String)>,
) -> Option<Box<ProxyHandle>> {
    // Point AppPaths at the container the extension gave us.
    unsafe { std::env::set_var("LINUXDO_IOS_HOME", &home_dir) };

    let config: AppConfig = match config_toml {
        Some(text) => toml::from_str(&text).unwrap_or_default(),
        None => AppConfig::default(),
    };

    let paths = AppPaths::resolve(None).ok()?;
    paths.ensure_layout().ok()?;
    // If the app passed certs (via providerConfiguration), write and use those
    // so the extension serves exactly the CA the app installed. Otherwise
    // generate a bundle locally.
    let bundle = match provided_certs {
        Some((ca, cert, key)) => {
            certs::install_bundle_pems(&paths.cert_dir, &ca, &cert, &key).ok()?
        }
        None => certs::ensure_bundle(&config, &paths.cert_dir).ok()?,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let thread = std::thread::Builder::new()
        .name("linuxdo-ios-proxy".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            let _ = runtime.block_on(proxy::run_proxy(config, paths, bundle, shutdown_rx));
        })
        .ok()?;

    Some(Box::new(ProxyHandle {
        shutdown_tx,
        thread: Some(thread),
    }))
}

/// Starts the proxy. `config_toml` may be null (uses defaults). `home_dir` is
/// the writable container path. Returns an opaque handle or null on error.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn linuxdo_proxy_start(
    config_toml: *const c_char,
    home_dir: *const c_char,
) -> *mut ProxyHandle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let home = cstr_to_string(home_dir)?;
        start_inner(cstr_to_string(config_toml), home, None)
    }));
    match result {
        Ok(Some(handle)) => Box::into_raw(handle),
        _ => std::ptr::null_mut(),
    }
}

/// Starts the proxy using caller-provided cert PEMs (from the app via
/// providerConfiguration) instead of generating them. Returns null on error.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn linuxdo_proxy_start_with_certs(
    config_toml: *const c_char,
    home_dir: *const c_char,
    ca_pem: *const c_char,
    server_cert_pem: *const c_char,
    server_key_pem: *const c_char,
) -> *mut ProxyHandle {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let home = cstr_to_string(home_dir)?;
        let ca = cstr_to_string(ca_pem)?;
        let cert = cstr_to_string(server_cert_pem)?;
        let key = cstr_to_string(server_key_pem)?;
        start_inner(cstr_to_string(config_toml), home, Some((ca, cert, key)))
    }));
    match result {
        Ok(Some(handle)) => Box::into_raw(handle),
        _ => std::ptr::null_mut(),
    }
}

/// Signals shutdown and joins the runtime thread. Consumes the handle.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn linuxdo_proxy_stop(handle: *mut ProxyHandle) {
    if handle.is_null() {
        return;
    }
    let mut boxed = unsafe { Box::from_raw(handle) };
    let _ = boxed.shutdown_tx.send(true);
    if let Some(thread) = boxed.thread.take() {
        let _ = thread.join();
    }
}

/// Writes the CA DER bytes into a freshly allocated buffer; sets `*out_len` and
/// returns the pointer (free with `linuxdo_free_bytes`). Returns null on error.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn linuxdo_export_ca_der(
    config_toml: *const c_char,
    home_dir: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    let result = catch_unwind(AssertUnwindSafe(|| -> anyhow::Result<Vec<u8>> {
        let home = cstr_to_string(home_dir)
            .ok_or_else(|| anyhow::anyhow!("home_dir is null"))?;
        unsafe { std::env::set_var("LINUXDO_IOS_HOME", &home) };
        let config: AppConfig = match cstr_to_string(config_toml) {
            Some(text) => toml::from_str(&text).unwrap_or_default(),
            None => AppConfig::default(),
        };
        let paths = AppPaths::resolve(None)?;
        paths.ensure_layout()?;
        certs::export_ca_der(&config, &paths.cert_dir)
    }));

    let result = match result {
        Ok(inner) => inner,
        Err(_) => Err(anyhow::anyhow!("panic during CA export")),
    };

    match result {
        Ok(mut der) => {
            der.shrink_to_fit();
            let len = der.len();
            let ptr = der.as_mut_ptr();
            std::mem::forget(der);
            if !out_len.is_null() {
                unsafe { *out_len = len };
            }
            ptr
        }
        Err(error) => {
            set_last_error(format!("{error:#}"));
            if !out_len.is_null() {
                unsafe { *out_len = 0 };
            }
            std::ptr::null_mut()
        }
    }
}

/// Ensures the bundle and returns it as a C string with three sections the app
/// splits on sentinel lines: CA PEM, server cert PEM, server key PEM. The app
/// installs the CA and passes cert+key to the extension. Free with
/// `linuxdo_free_cstr`; null on error (see `linuxdo_last_error`).
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn linuxdo_export_bundle(
    config_toml: *const c_char,
    home_dir: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| -> anyhow::Result<String> {
        let home = cstr_to_string(home_dir).ok_or_else(|| anyhow::anyhow!("home_dir is null"))?;
        unsafe { std::env::set_var("LINUXDO_IOS_HOME", &home) };
        let config: AppConfig = match cstr_to_string(config_toml) {
            Some(text) => toml::from_str(&text).unwrap_or_default(),
            None => AppConfig::default(),
        };
        let paths = AppPaths::resolve(None)?;
        paths.ensure_layout()?;
        let pems = certs::export_bundle_pems(&config, &paths.cert_dir)?;
        // Sentinel-delimited sections; PEM never contains these marker lines.
        Ok(format!(
            "-----LDA-CA-----\n{}\n-----LDA-CERT-----\n{}\n-----LDA-KEY-----\n{}",
            pems.ca_pem.trim(),
            pems.server_cert_pem.trim(),
            pems.server_key_pem.trim(),
        ))
    }));

    let result = match result {
        Ok(inner) => inner,
        Err(_) => Err(anyhow::anyhow!("panic during bundle export")),
    };

    match result {
        Ok(text) => CString::new(text)
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(error) => {
            set_last_error(format!("{error:#}"));
            std::ptr::null_mut()
        }
    }
}

/// Returns the last FFI error as a malloc'd C string (free with
/// `linuxdo_free_cstr`), or null if none. Used to diagnose export failures.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn linuxdo_last_error() -> *mut c_char {
    let msg = LAST_ERROR.lock().ok().and_then(|slot| slot.clone());
    match msg {
        Some(text) => CString::new(text)
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Frees a C string returned by `linuxdo_last_error`.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn linuxdo_free_cstr(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

/// Frees a buffer returned by `linuxdo_export_ca_der`.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn linuxdo_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

// Silence dead-code warnings for helpers on non-iOS builds where the exported
// entry points are compiled out.
#[cfg(not(target_os = "ios"))]
#[allow(dead_code)]
fn _keep_used() {
    let _ = start_inner
        as fn(Option<String>, String, Option<(String, String, String)>) -> Option<Box<ProxyHandle>>;
    let _ = cstr_to_string as fn(*const c_char) -> Option<String>;
    let _ = set_last_error::<String>;
}
