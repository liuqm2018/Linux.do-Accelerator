#ifndef LINUXDO_CORE_H
#define LINUXDO_CORE_H

#include <stddef.h>
#include <stdint.h>

/*
 * C ABI for the Rust ECH proxy core (liblinuxdo_accelerator.a).
 * Implemented in src/ffi_ios.rs. Symbols exist only in the iOS build.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle owning the proxy runtime thread. */
typedef struct ProxyHandle ProxyHandle;

/*
 * Starts the local TLS-terminating ECH proxy.
 *   config_toml : TOML config text, or NULL to use built-in defaults.
 *   home_dir    : writable container path (App Group). Certs/config live here.
 * Returns an opaque handle, or NULL on failure. Free with linuxdo_proxy_stop.
 */
ProxyHandle *linuxdo_proxy_start(const char *config_toml, const char *home_dir);

/* Signals shutdown, joins the runtime thread, and frees the handle. */
void linuxdo_proxy_stop(ProxyHandle *handle);

/*
 * Ensures the CA exists and returns its DER bytes (for device trust install).
 *   out_len : receives the byte length.
 * Returns a malloc'd buffer (free with linuxdo_free_bytes), or NULL on failure.
 */
uint8_t *linuxdo_export_ca_der(const char *config_toml, const char *home_dir, size_t *out_len);

/* Frees a buffer returned by linuxdo_export_ca_der. */
void linuxdo_free_bytes(uint8_t *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LINUXDO_CORE_H */
