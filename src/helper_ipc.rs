use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::state::ServiceState;

const SOCKET_NAME: &str = "io.linuxdo.accelerator.helper.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperRequest {
    Start { config_path: PathBuf },
    Stop { config_path: PathBuf },
    Status { config_path: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ServiceState>,
}

pub fn socket_path() -> PathBuf {
    Path::new("/tmp").join(SOCKET_NAME)
}

/// Send a request to the privileged helper daemon and return the response.
pub fn send_request(socket: &Path, request: &HelperRequest) -> Result<HelperResponse> {
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("failed to connect to {socket:?}"))?;

    let payload =
        serde_json::to_string(request).context("failed to serialize helper request")?;
    writeln!(stream, "{payload}").context("failed to write helper request")?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("failed to read helper response")?;

    let response: HelperResponse =
        serde_json::from_str(line.trim()).context("failed to parse helper response")?;
    Ok(response)
}

/// Run the privileged helper server. Calls `handler` for each request.
/// The handler receives the request and should return a response.
pub fn run_server<F>(socket: &Path, handler: F) -> Result<()>
where
    F: Fn(&HelperRequest) -> HelperResponse,
{
    // Remove stale socket if it exists.
    let _ = std::fs::remove_file(socket);

    let listener =
        UnixListener::bind(socket).with_context(|| format!("failed to bind {socket:?}"))?;

    // Allow the current user (and group) to connect.
    // The socket is created owned by root; set permissions so the user can connect.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666));
    }

    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // Verify peer UID matches the real user (not root).
                #[cfg(unix)]
                {
                    if let Ok(peer_cred) = peer_cred(&stream) {
                        let real_uid = real_user_uid();
                        if real_uid != 0 && peer_cred != real_uid {
                            let resp = HelperResponse {
                                success: false,
                                message: format!(
                                    "rejected: peer uid {peer_cred} != expected {real_uid}"
                                ),
                                status: None,
                            };
                            let _ = write_response(&stream, &resp);
                            continue;
                        }
                    }
                }
                handle_client(&stream, &handler);
            }
            Err(e) => {
                eprintln!("helper accept error: {e}");
            }
        }
    }
}

fn handle_client(stream: &UnixStream, handler: &dyn Fn(&HelperRequest) -> HelperResponse) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if let Err(e) = reader.read_line(&mut line) {
        eprintln!("helper read error: {e}");
        return;
    }

    let request: HelperRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = HelperResponse {
                success: false,
                message: format!("invalid request: {e}"),
                status: None,
            };
            let _ = write_response(stream, &resp);
            return;
        }
    };

    let response = handler(&request);
    let _ = write_response(stream, &response);
}

fn write_response(mut stream: &UnixStream, response: &HelperResponse) -> Result<()> {
    let payload = serde_json::to_string(response).context("failed to serialize response")?;
    writeln!(stream, "{payload}").context("failed to write response")?;
    Ok(())
}

/// Get the peer UID of a Unix domain socket connection.
#[cfg(unix)]
fn peer_cred(stream: &UnixStream) -> Result<u32> {
    // macOS uses LOCAL_PEERCRED, Linux uses SO_PEERCRED.
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
        let mut cred_len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                &mut cred as *mut _ as *mut _,
                &mut cred_len,
            )
        };
        if ret != 0 {
            anyhow::bail!("getsockopt LOCAL_PEERCRED failed");
        }
        Ok(cred.cr_uid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut cred_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut _,
                &mut cred_len,
            )
        };
        if ret != 0 {
            anyhow::bail!("getsockopt SO_PEERCRED failed");
        }
        Ok(cred.uid)
    }
}

/// Get the real user UID (from SUDO_UID or the current process UID).
fn real_user_uid() -> u32 {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getuid() })
}
