use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use crate::platform::{is_elevated, run_elevated};
use anyhow::{Context, Result, bail};

#[cfg(target_os = "macos")]
const AUTOSTART_LABEL: &str = "io.linuxdo.accelerator";
#[cfg(any(target_os = "windows", target_os = "linux"))]
const AUTOSTART_DISPLAY_NAME: &str = "Linux.do Accelerator";
#[cfg(target_os = "windows")]
const AUTOSTART_TASK_NAME: &str = AUTOSTART_DISPLAY_NAME;
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
const AUTOSTART_FLAG: &str = "--autostart";

pub fn enable(config_path: &Path) -> Result<()> {
    let exe = std::env::current_exe().context("failed to locate current executable")?;
    enable_for_exe(&exe, config_path)
}

pub fn disable() -> Result<()> {
    platform_disable()
}

pub fn is_enabled() -> bool {
    platform_is_enabled().unwrap_or(false)
}

fn enable_for_exe(exe: &Path, config_path: &Path) -> Result<()> {
    platform_enable(exe, config_path)
}

#[cfg(target_os = "windows")]
fn platform_enable(exe: &Path, config_path: &Path) -> Result<()> {
    use std::process::Command;

    if !is_elevated() {
        return rerun_windows_autostart_command(exe, Some(config_path), "enable-autostart");
    }

    let exe = absolute_display_path(exe);
    let config = absolute_display_path(config_path);
    let value = windows_task_action(&exe, &config);

    let mut command = Command::new("schtasks");
    command.args([
        "/create",
        "/tn",
        AUTOSTART_TASK_NAME,
        "/sc",
        "onlogon",
        "/rl",
        "HIGHEST",
        "/tr",
        &value,
        "/f",
    ]);
    hide_windows_window(&mut command);
    let output = command.output().context("failed to invoke schtasks.exe")?;
    if !output.status.success() {
        bail!(
            "schtasks /create failed: {}",
            windows_command_message(&output)
        );
    }
    configure_windows_task_settings()?;
    remove_legacy_windows_run_entry()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_disable() -> Result<()> {
    use std::process::Command;

    let scheduled_task_exists = windows_scheduled_task_exists()?;
    if scheduled_task_exists && !is_elevated() {
        let exe = std::env::current_exe().context("failed to locate current executable")?;
        return rerun_windows_autostart_command(&exe, None, "disable-autostart");
    }

    if scheduled_task_exists {
        let mut command = Command::new("schtasks");
        command.args(["/delete", "/tn", AUTOSTART_TASK_NAME, "/f"]);
        hide_windows_window(&mut command);
        let output = command.output().context("failed to invoke schtasks.exe")?;
        if !output.status.success() {
            bail!(
                "schtasks /delete failed: {}",
                windows_command_message(&output)
            );
        }
    }

    remove_legacy_windows_run_entry()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_is_enabled() -> Result<bool> {
    windows_scheduled_task_exists()
}

#[cfg(target_os = "windows")]
fn rerun_windows_autostart_command(
    executable: &Path,
    config_path: Option<&Path>,
    subcommand: &str,
) -> Result<()> {
    let mut args = Vec::with_capacity(3);
    if let Some(config_path) = config_path {
        args.push("--config".to_string());
        args.push(absolute_display_path(config_path));
    }
    args.push(subcommand.to_string());
    run_elevated(executable, &args)
        .with_context(|| format!("failed to rerun {subcommand} with administrator privileges"))
}

#[cfg(target_os = "windows")]
fn windows_scheduled_task_exists() -> Result<bool> {
    use std::process::Command;

    let mut command = Command::new("schtasks");
    command.args(["/query", "/tn", AUTOSTART_TASK_NAME]);
    hide_windows_window(&mut command);
    let output = command.output().context("failed to invoke schtasks.exe")?;
    Ok(output.status.success())
}

#[cfg(target_os = "windows")]
fn remove_legacy_windows_run_entry() -> Result<()> {
    use std::process::Command;

    let mut command = Command::new("reg");
    command.args([
        "delete",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "/v",
        AUTOSTART_DISPLAY_NAME,
        "/f",
    ]);
    hide_windows_window(&mut command);
    let output = command.output().context("failed to invoke reg.exe")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if stderr.contains("unable to find") || stderr.contains("找不到") {
            return Ok(());
        }
        bail!(
            "reg delete failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn configure_windows_task_settings() -> Result<()> {
    use std::process::Command;

    let task_name = powershell_single_quoted(AUTOSTART_TASK_NAME);
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $settings = New-ScheduledTaskSettingsSet \
           -AllowStartIfOnBatteries \
           -DontStopIfGoingOnBatteries \
           -StartWhenAvailable \
           -ExecutionTimeLimit (New-TimeSpan -Hours 72); \
         Set-ScheduledTask -TaskName {task_name} -Settings $settings | Out-Null"
    );

    let mut command = Command::new("powershell");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &script,
    ]);
    hide_windows_window(&mut command);
    let output = command
        .output()
        .context("failed to invoke powershell.exe")?;
    if !output.status.success() {
        bail!(
            "Set-ScheduledTask settings failed: {}",
            windows_command_message(&output)
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn powershell_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(target_os = "windows")]
fn windows_task_action(exe: &str, config: &str) -> String {
    format!("\"{exe}\" --config \"{config}\" {AUTOSTART_FLAG} gui")
}

#[cfg(target_os = "windows")]
fn windows_command_message(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[cfg(target_os = "windows")]
fn hide_windows_window(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(target_os = "macos")]
fn platform_enable(exe: &Path, config_path: &Path) -> Result<()> {
    use std::fs;

    let plist_path = macos_plist_path()?;
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let exe = absolute_display_path(exe);
    let config = absolute_display_path(config_path);
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--config</string>
        <string>{config}</string>
        <string>{flag}</string>
        <string>gui</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
        label = AUTOSTART_LABEL,
        exe = xml_escape(&exe),
        config = xml_escape(&config),
        flag = AUTOSTART_FLAG,
    );

    fs::write(&plist_path, plist)
        .with_context(|| format!("failed to write {}", plist_path.display()))?;

    let _ = std::process::Command::new("launchctl")
        .args(["unload", &plist_path.to_string_lossy()])
        .output();
    let _ = std::process::Command::new("launchctl")
        .args(["load", &plist_path.to_string_lossy()])
        .output();
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_disable() -> Result<()> {
    use std::fs;

    let plist_path = macos_plist_path()?;
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .output();
        fs::remove_file(&plist_path)
            .with_context(|| format!("failed to remove {}", plist_path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_is_enabled() -> Result<bool> {
    Ok(macos_plist_path()
        .map(|path| path.exists())
        .unwrap_or(false))
}

#[cfg(target_os = "macos")]
fn macos_plist_path() -> Result<PathBuf> {
    let home = home_dir().context("failed to resolve user home directory")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{AUTOSTART_LABEL}.plist")))
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------------------------------------------------------------------------
// macOS privileged helper (LaunchDaemon) management
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const HELPER_LABEL: &str = "io.linuxdo.accelerator.helper";

#[cfg(target_os = "macos")]
fn helper_plist_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/Library/LaunchDaemons").join(format!("{HELPER_LABEL}.plist"))
}

/// Check whether the privileged helper LaunchDaemon is installed and loaded.
#[cfg(target_os = "macos")]
pub fn is_privileged_helper_installed() -> bool {
    let plist = helper_plist_path();
    if !plist.exists() {
        return false;
    }
    // Also verify launchd knows about it.
    std::process::Command::new("launchctl")
        .args(["list", HELPER_LABEL])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Install the privileged helper LaunchDaemon.  Requires administrator privileges
/// (triggers a one-time password prompt via osascript).
#[cfg(target_os = "macos")]
pub fn install_privileged_helper(exe: &std::path::Path, config_path: &std::path::Path) -> Result<()> {
    use std::fs;

    let plist_path = helper_plist_path();
    let exe = absolute_display_path(exe);
    let config = absolute_display_path(config_path);

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--config</string>
        <string>{config}</string>
        <string>privileged-helper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Standard</string>
</dict>
</plist>
"#,
        label = HELPER_LABEL,
        exe = xml_escape(&exe),
        config = xml_escape(&config),
    );

    // Write the plist and load it via an elevated osascript call (one-time prompt).
    let script = format!(
        "do shell script \"mkdir -p /Library/LaunchDaemons && cat > {plist_path} <<'PLIST_EOF'\n{plist}\nPLIST_EOF\nlaunchctl unload -w {plist_path} 2>/dev/null; launchctl load -w {plist_path}\" with prompt \"Linux.do Accelerator 需要安装特权辅助进程以实现免密码加速。\" with administrator privileges",
        plist_path = plist_path.display(),
        plist = plist,
    );

    // We need to write the plist content through osascript because the target
    // directory is root-owned.  Use a temp file approach for reliability.
    let tmp = std::env::temp_dir().join(format!("{HELPER_LABEL}.plist"));
    fs::write(&tmp, &plist).context("failed to write temporary plist")?;

    let install_script = format!(
        "do shell script \"cp '{tmp}' '{dest}' && launchctl unload -w '{dest}' 2>/dev/null; launchctl load -w '{dest}'\" with prompt \"Linux.do Accelerator 需要安装特权辅助进程以实现免密码加速。\" with administrator privileges",
        tmp = tmp.display(),
        dest = plist_path.display(),
    );

    crate::platform::run_command("osascript", &["-e", &install_script])
        .context("failed to install privileged helper (osascript)")?;

    // Clean up temp file.
    let _ = fs::remove_file(&tmp);

    // Give launchd a moment to start the helper.
    std::thread::sleep(std::time::Duration::from_millis(500));

    Ok(())
}

/// Uninstall the privileged helper LaunchDaemon.
#[cfg(target_os = "macos")]
pub fn uninstall_privileged_helper() -> Result<()> {
    let plist_path = helper_plist_path();
    if !plist_path.exists() {
        return Ok(());
    }

    let script = format!(
        "do shell script \"launchctl unload -w '{plist}' 2>/dev/null; rm -f '{plist}'\" with prompt \"Linux.do Accelerator 需要卸载特权辅助进程。\" with administrator privileges",
        plist = plist_path.display(),
    );

    crate::platform::run_command("osascript", &["-e", &script])
        .context("failed to uninstall privileged helper")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux privileged helper (systemd user service) management
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const HELPER_SERVICE_NAME: &str = "linuxdo-accelerator-helper";

#[cfg(target_os = "linux")]
fn helper_service_path() -> Result<PathBuf> {
    // Use a system-level service so it runs as root without per-user setup.
    Ok(PathBuf::from("/etc/systemd/system")
        .join(format!("{HELPER_SERVICE_NAME}.service")))
}

/// Check whether the privileged helper systemd service is installed and active.
#[cfg(target_os = "linux")]
pub fn is_privileged_helper_installed() -> bool {
    let Ok(path) = helper_service_path() else {
        return false;
    };
    if !path.exists() {
        return false;
    }
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", HELPER_SERVICE_NAME])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Install the privileged helper as a systemd service.  Requires root (pkexec).
#[cfg(target_os = "linux")]
pub fn install_privileged_helper(exe: &std::path::Path, config_path: &std::path::Path) -> Result<()> {
    use std::fs;

    let service_path = helper_service_path()?;
    let exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let config = config_path.canonicalize().unwrap_or_else(|_| config_path.to_path_buf());

    let unit = format!(
        r#"[Unit]
Description=Linux.do Accelerator Privileged Helper
After=network.target

[Service]
Type=simple
ExecStart={exe} --config {config} privileged-helper
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"#,
        exe = exe.display(),
        config = config.display(),
    );

    // Write the unit file via pkexec (one-time root prompt).
    let tmp = std::env::temp_dir().join(format!("{HELPER_SERVICE_NAME}.service"));
    fs::write(&tmp, &unit).context("failed to write temporary service file")?;

    let dest = service_path.display();
    let status = std::process::Command::new("pkexec")
        .args([
            "bash",
            "-c",
            &format!(
                "cp '{tmp}' '{dest}' && systemctl daemon-reload && systemctl enable --now '{name}'",
                tmp = tmp.display(),
                dest = dest,
                name = HELPER_SERVICE_NAME,
            ),
        ])
        .status()
        .context("failed to execute pkexec")?;

    let _ = fs::remove_file(&tmp);

    if !status.success() {
        bail!("pkexec rejected the request or systemctl failed");
    }

    // Give systemd a moment to start the helper.
    std::thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}

/// Uninstall the privileged helper systemd service.
#[cfg(target_os = "linux")]
pub fn uninstall_privileged_helper() -> Result<()> {
    let Ok(path) = helper_service_path() else {
        return Ok(());
    };
    if !path.exists() {
        return Ok(());
    }

    let status = std::process::Command::new("pkexec")
        .args([
            "bash",
            "-c",
            &format!(
                "systemctl disable --now '{name}' 2>/dev/null; rm -f '{path}' && systemctl daemon-reload",
                name = HELPER_SERVICE_NAME,
                path = path.display(),
            ),
        ])
        .status()
        .context("failed to execute pkexec")?;

    if !status.success() {
        bail!("pkexec rejected the request or systemctl failed");
    }
    Ok(())
}

// Non-Unix stubs (Windows, Android, etc.)
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn is_privileged_helper_installed() -> bool {
    false
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn install_privileged_helper(_exe: &std::path::Path, _config_path: &std::path::Path) -> Result<()> {
    bail!("privileged helper is not supported on this platform")
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn uninstall_privileged_helper() -> Result<()> {
    bail!("privileged helper is not supported on this platform")
}

#[cfg(target_os = "linux")]
fn platform_enable(exe: &Path, config_path: &Path) -> Result<()> {
    use std::fs;

    let desktop_path = linux_desktop_path()?;
    if let Some(parent) = desktop_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let exec = format!(
        "{} --config {} {} gui",
        desktop_quote(&absolute_display_path(exe)),
        desktop_quote(&absolute_display_path(config_path)),
        AUTOSTART_FLAG,
    );

    let contents = format!(
        "[Desktop Entry]\nType=Application\nName={name}\nExec={exec}\nIcon=linuxdo-accelerator\nTerminal=false\nStartupNotify=false\nX-GNOME-Autostart-enabled=true\n",
        name = AUTOSTART_DISPLAY_NAME,
        exec = exec,
    );

    fs::write(&desktop_path, contents)
        .with_context(|| format!("failed to write {}", desktop_path.display()))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_disable() -> Result<()> {
    use std::fs;

    let desktop_path = linux_desktop_path()?;
    if desktop_path.exists() {
        fs::remove_file(&desktop_path)
            .with_context(|| format!("failed to remove {}", desktop_path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_is_enabled() -> Result<bool> {
    Ok(linux_desktop_path()
        .map(|path| path.exists())
        .unwrap_or(false))
}

#[cfg(target_os = "linux")]
fn linux_desktop_path() -> Result<PathBuf> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".config")))
        .context("failed to resolve user config directory")?;
    Ok(config_home
        .join("autostart")
        .join("linuxdo-accelerator.desktop"))
}

#[cfg(target_os = "linux")]
fn desktop_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
fn absolute_display_path(path: &Path) -> String {
    let resolved = path
        .canonicalize()
        .ok()
        .or_else(|| std::path::absolute(path).ok())
        .unwrap_or_else(|| path.to_path_buf());
    let display = resolved.to_string_lossy().into_owned();
    strip_extended_length_prefix(display)
}

#[cfg(target_os = "windows")]
fn strip_extended_length_prefix(value: String) -> String {
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = value.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    value
}

#[cfg(not(target_os = "windows"))]
fn strip_extended_length_prefix(value: String) -> String {
    value
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn platform_enable(_exe: &Path, _config_path: &Path) -> Result<()> {
    bail!("autostart is not supported on this platform")
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn platform_disable() -> Result<()> {
    bail!("autostart is not supported on this platform")
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn platform_is_enabled() -> Result<bool> {
    Ok(false)
}
