//! ADB helpers for the developer's own device.
//! A failing command is tried once and then at most twice more.

use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdbDevice {
    pub serial: String,
    pub emulator: bool,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct ConnectRequest {
    pub serial: String,
    pub port: u16,
    pub ca_cer: String,
    pub fingerprint: String,
    pub apk: Option<String>,
}

pub fn parse_devices(output: &str) -> Vec<AdbDevice> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("List of devices") {
                return None;
            }
            let mut parts = line.split_whitespace();
            let serial = parts.next()?.to_string();
            let state = parts.next().unwrap_or("");
            if state != "device" {
                return None;
            }
            let detail = parts.collect::<Vec<_>>().join(" ");
            let emulator = serial.starts_with("emulator-")
                || detail.contains("emulator")
                || detail.contains("sdk_gphone");
            Some(AdbDevice {
                serial,
                emulator,
                detail,
            })
        })
        .collect()
}

pub fn run_command(program: &str, args: &[String]) -> Result<String, String> {
    let mut last = String::new();
    for attempt in 0..3 {
        match Command::new(program).args(args).output() {
            Ok(output) if output.status.success() => {
                let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
                if text.trim().is_empty() {
                    text = String::from_utf8_lossy(&output.stderr).into_owned();
                }
                return Ok(text);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                last = format!(
                    "{program} {} failed ({}): {stderr}{stdout}",
                    args.join(" "),
                    output.status
                );
            }
            Err(err) => {
                last = format!("{program} {} could not start: {err}", args.join(" "));
                if err.kind() == ErrorKind::NotFound {
                    return Err(last);
                }
            }
        }
        if attempt < 2 {
            thread::sleep(Duration::from_millis(150));
        }
    }
    Err(last)
}

pub fn connect_android<F>(request: &ConnectRequest, mut run: F) -> String
where
    F: FnMut(&str, &[String]) -> Result<String, String>,
{
    let devices = match run("adb", &["devices".into(), "-l".into()]) {
        Ok(text) => parse_devices(&text),
        Err(err) => return format!("Android connect stopped. {err}"),
    };
    if devices.is_empty() {
        return "No Android device is attached. Manual proxy mode is still available. Plug in a device, accept the USB debugging prompt, and press Connect Android again.".into();
    }
    let Some(device) = devices.iter().find(|device| device.serial == request.serial) else {
        let known = devices
            .iter()
            .map(|device| device.serial.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "Device {} is not in `adb devices`. Attached: {known}.",
            request.serial
        );
    };
    let serial = device.serial.clone();
    let port = request.port.to_string();
    if let Err(err) = run(
        "adb",
        &[
            "-s".into(),
            serial.clone(),
            "reverse".into(),
            format!("tcp:{port}"),
            format!("tcp:{port}"),
        ],
    ) {
        return format!("adb reverse failed, so the phone cannot reach the proxy yet. {err}");
    }
    if let Err(err) = run(
        "adb",
        &[
            "-s".into(),
            serial.clone(),
            "push".into(),
            request.ca_cer.clone(),
            "/sdcard/Download/app-network-watcher-ca.crt".into(),
        ],
    ) {
        return format!("The CA was not copied to the device. {err}");
    }
    let apk_note = if let Some(apk) = &request.apk {
        if Path::new(apk).is_file() {
            match run(
                "adb",
                &["-s".into(), serial.clone(), "install".into(), "-r".into(), apk.clone()],
            ) {
                Ok(_) => "Companion installed.".into(),
                Err(err) => format!("Companion install failed. {err}"),
            }
        } else {
            "No companion APK is built. The project is in android/. Install it once a device and the Android SDK are available.".into()
        }
    } else {
        "No companion APK path was set.".into()
    };
    let launch = run(
        "adb",
        &[
            "-s".into(),
            serial.clone(),
            "shell".into(),
            "am".into(),
            "start".into(),
            "-n".into(),
            "com.appnetworkwatcher/.MainActivity".into(),
            "--es".into(),
            "host".into(),
            "127.0.0.1".into(),
            "--ei".into(),
            "port".into(),
            port,
            "--es".into(),
            "fp".into(),
            request.fingerprint.clone(),
        ],
    );
    match launch {
        Ok(_) => format!(
            "Waiting for you to approve the VPN and certificate prompts on {serial}. Interception stays off until both approvals show up. {apk_note}"
        ),
        Err(err) => format!(
            "The companion did not launch. Approve USB debugging and install android/ first. {err} {apk_note}"
        ),
    }
}

pub fn check_approval<F>(serial: &str, port: u16, mut run: F) -> String
where
    F: FnMut(&str, &[String]) -> Result<String, String>,
{
    let log = match run(
        "adb",
        &[
            "-s".into(),
            serial.into(),
            "logcat".into(),
            "-d".into(),
            "-s".into(),
            "WatcherVpn:I".into(),
        ],
    ) {
        Ok(text) => text,
        Err(err) => return format!("Could not read the device log. {err}"),
    };
    let vpn = log.contains("VPN_READY");
    let cert = log.contains("CERT_APPROVED");
    if !vpn || !cert {
        return format!(
            "Still waiting on {serial}. VPN approved: {vpn}. Certificate approved: {cert}. The proxy is not the device HTTP proxy until both are true."
        );
    }
    let port = port.to_string();
    if let Err(err) = run(
        "adb",
        &[
            "-s".into(),
            serial.into(),
            "shell".into(),
            "settings".into(),
            "put".into(),
            "global".into(),
            "http_proxy".into(),
            format!("127.0.0.1:{port}"),
        ],
    ) {
        return format!(
            "VPN and CA are approved on {serial}, but the process HTTP proxy was not set. {err}"
        );
    }
    format!(
        "VPN and CA are active on {serial}. The device HTTP proxy is 127.0.0.1:{port} through adb reverse. Traffic from apps that trust this CA is captured on this computer."
    )
}

pub fn install_system_ca<F>(
    confirmed: bool,
    emulator_or_rooted: bool,
    serial: &str,
    ca_pem: &str,
    mut run: F,
) -> String
where
    F: FnMut(&str, &[String]) -> Result<String, String>,
{
    if !confirmed {
        return "System CA install did not run. Tick the confirmation first. It is only for an emulator or a device that is already rooted.".into();
    }
    if !emulator_or_rooted {
        return "System CA install did not run. The selected device is not an emulator, and it is not marked as already rooted.".into();
    }
    if let Err(err) = run("adb", &["-s".into(), serial.into(), "root".into()]) {
        return format!(
            "adb root is not available on {serial}, so the system store was not changed. {err}"
        );
    }
    let _ = run("adb", &["-s".into(), serial.into(), "wait-for-device".into()]);
    let id = match run("adb", &["-s".into(), serial.into(), "shell".into(), "id".into()]) {
        Ok(text) => text,
        Err(err) => {
            return format!("Could not check whether adb root actually worked. {err}");
        }
    };
    if !id.contains("uid=0") {
        return format!(
            "adb root returned, but the shell is not root (`{id}`). The system store was not changed."
        );
    }
    let hash = match run(
        "openssl",
        &[
            "x509".into(),
            "-in".into(),
            ca_pem.into(),
            "-subject_hash_old".into(),
            "-noout".into(),
        ],
    ) {
        Ok(text) => text.trim().to_string(),
        Err(err) => {
            return format!("openssl could not hash the CA, so the system store was not changed. {err}");
        }
    };
    if hash.is_empty() || hash.contains('/') || hash.contains(' ') {
        return format!("The CA hash `{hash}` is not usable. The system store was not changed.");
    }
    let remote = format!("/sdcard/Download/{hash}.0");
    let system = format!("/system/etc/security/cacerts/{hash}.0");
    if let Err(err) = run(
        "adb",
        &["-s".into(), serial.into(), "push".into(), ca_pem.into(), remote.clone()],
    ) {
        return format!("The CA was not pushed. {err}");
    }
    let command = format!(
        "mount -o rw,remount /system || mount -o rw,remount /; cp {remote} {system} && chmod 644 {system}"
    );
    match run(
        "adb",
        &["-s".into(), serial.into(), "shell".into(), command],
    ) {
        Ok(_) => format!(
            "System CA {hash}.0 was copied on {serial}. Reboot the emulator or device, then apps that trust the system store can be captured. This includes release builds that do not have a user-CA exception. Apps that pin certificates still fail."
        ),
        Err(err) => format!("The system store copy failed. {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_emulator_and_phone() {
        let text = "\
List of devices attached
emulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a
R58N1234               device usb:1-1 product:dm1q model:SM_S911B device:dm1q
unauthorized           unauthorized
";
        let devices = parse_devices(text);
        assert_eq!(devices.len(), 2);
        assert!(devices[0].emulator);
        assert!(!devices[1].emulator);
    }

    #[test]
    fn system_store_refuses_without_confirmation() {
        let mut calls = 0;
        let message = install_system_ca(false, true, "emulator-5554", "ca.pem", |_, _| {
            calls += 1;
            Ok(String::new())
        });
        assert_eq!(calls, 0);
        assert!(message.contains("did not run"));
    }

    #[test]
    fn connect_stops_when_no_device_is_attached() {
        let request = ConnectRequest {
            serial: "emulator-5554".into(),
            port: 8080,
            ca_cer: "ca.cer".into(),
            fingerprint: "aa".into(),
            apk: None,
        };
        let message = connect_android(&request, |_, args| {
            assert_eq!(args, &["devices".to_string(), "-l".to_string()]);
            Ok("List of devices attached\n".into())
        });
        assert!(message.contains("No Android device"));
    }
}
