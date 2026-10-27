//! Keeps license request material out of stderr (arkavo-rs#83).
//!
//! The vendored FairPlay SDK logs with `eprintln!`, and some of its error lines carry
//! the request: its panic handler prints the whole input JSON (content key, IV, SPC),
//! and its key and IV decode errors print the key or IV. `vendor/fpssdk` is Apple's
//! code and is not modified, so arks routes the process's stderr through a pipe
//! instead: a thread forwards every line to the real stderr, but an SDK line
//! (`FP_ERRCODE=`) naming one of those messages is cut after its error code.
//!
//! The wrapper already refuses key and IV material the SDK would have to repair
//! (#82), so those lines need a malformed request; the panic line needs an SDK bug,
//! which an attacker-chosen SPC could reach.

use std::borrow::Cow;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::FromRawFd;
use std::sync::Mutex;

/// The real stderr and the forwarding thread, for [`finish`].
static INSTALLED: Mutex<Option<(libc::c_int, std::thread::JoinHandle<()>)>> = Mutex::new(None);

/// SDK messages that print license request material after them.
const SENSITIVE: [&str; 5] = [
    "panic input:",
    "content key invalid length",
    "unable to decode content key",
    "content iv invalid length",
    "unable to decode content iv",
];

const SDK_ERROR_FIELD: &str = "FP_ERRCODE=";

/// The line as it may be written: an SDK error line naming a sensitive message keeps
/// its prefix and error code, and the rest is replaced.
pub fn scrub_line(line: &str) -> Cow<'_, str> {
    let Some(field) = line.find(SDK_ERROR_FIELD) else {
        return Cow::Borrowed(line);
    };
    let lower = line.to_ascii_lowercase();
    if !SENSITIVE.iter().any(|m| lower.contains(m)) {
        return Cow::Borrowed(line);
    }
    // Keep `FP_ERRCODE="<code>"`; the code is a number, so it carries nothing secret.
    let after = &line[field + SDK_ERROR_FIELD.len()..];
    let code_end = after
        .strip_prefix('"')
        .and_then(|rest| rest.find('"').map(|i| i + 2))
        .unwrap_or(0);
    let kept = &line[..field + SDK_ERROR_FIELD.len() + code_end];
    Cow::Owned(format!(
        "{kept} [fpssdk message redacted: it carried license request material, arkavo-rs#83]"
    ))
}

/// Routes fd 2 through [`scrub_line`]. Call once, before any thread writes to stderr.
/// On failure stderr is left as it was and the error is returned.
pub fn install() -> std::io::Result<()> {
    // SAFETY: plain fd syscalls on descriptors this function owns; fd 2 is replaced
    // atomically by dup2, so a concurrent writer sees either the old or the new target.
    unsafe {
        let real = libc::dup(2);
        if real < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut fds = [0; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(real);
            return Err(e);
        }
        let (read_end, write_end) = (fds[0], fds[1]);
        libc::fcntl(read_end, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(real, libc::F_SETFD, libc::FD_CLOEXEC);
        if libc::dup2(write_end, 2) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(read_end);
            libc::close(write_end);
            libc::close(real);
            return Err(e);
        }
        libc::close(write_end);
        let reader = std::fs::File::from_raw_fd(read_end);
        let forward = libc::dup(real);
        if forward < 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::fcntl(forward, libc::F_SETFD, libc::FD_CLOEXEC);
        let mut out = std::fs::File::from_raw_fd(forward);
        let handle = std::thread::Builder::new()
            .name("stderr-scrub".into())
            .spawn(move || {
                let mut lines = BufReader::new(reader);
                let mut buf = Vec::new();
                while matches!(lines.read_until(b'\n', &mut buf), Ok(n) if n > 0) {
                    let text = String::from_utf8_lossy(&buf);
                    let had_newline = text.ends_with('\n');
                    let line = text.trim_end_matches('\n');
                    let _ = out.write_all(scrub_line(line).as_bytes());
                    if had_newline {
                        let _ = out.write_all(b"\n");
                    }
                    buf.clear();
                }
            })?;
        *INSTALLED.lock().unwrap_or_else(|p| p.into_inner()) = Some((real, handle));
    }
    // A main-thread panic ends the process: drain what it wrote first
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        if std::thread::current().name() == Some("main") {
            finish();
        }
    }));
    Ok(())
}

/// Points fd 2 back at the real stderr and waits for the forwarding thread to write
/// out what is still in the pipe. Call before the process exits, so its last lines
/// (a startup error, a panic) are not lost. Later stderr writes are not scrubbed.
pub fn finish() {
    let Some((real, handle)) = INSTALLED.lock().unwrap_or_else(|p| p.into_inner()).take() else {
        return;
    };
    // SAFETY: `real` is the dup of the original stderr kept by `install`. Replacing
    // fd 2 closes the pipe's only write end, so the thread reads to EOF and returns.
    unsafe {
        libc::dup2(real, 2);
        libc::close(real);
    }
    let _ = handle.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f";

    /// A line exactly as `fpsLogError!` formats it (default empty log prefix)
    fn sdk_line(code: i32, message: &str) -> String {
        format!(",FP_ERRCODE=\"{code}\",{message}")
    }

    #[test]
    fn panic_input_and_key_errors_are_cut_after_the_error_code() {
        for message in [
            format!(
                "fpssdk panic: Any {{ .. }}, panic input: {{\"content-key\":\"{KEY}\",\"spc\":\"AAAA\"}}"
            ),
            format!("Warning! content key invalid length: \"{KEY}\""),
            format!("unable to decode content key: \"{KEY}\""),
            format!("Warning! content iv invalid length: \"{KEY}\""),
            format!("unable to decode content iv: \"{KEY}\""),
        ] {
            let line = sdk_line(-42585, &message);
            let scrubbed = scrub_line(&line);
            assert!(!scrubbed.contains(KEY), "{scrubbed}");
            assert!(!scrubbed.contains("AAAA"), "{scrubbed}");
            assert!(scrubbed.starts_with(",FP_ERRCODE=\"-42585\" [fpssdk message redacted"));
        }
    }

    #[test]
    fn other_lines_pass_through() {
        for line in [
            sdk_line(-42583, "SPC not found"),
            sdk_line(-42585, "Error decoding base64 SPC: Invalid byte"),
            "[2026-10-26T00:00:00Z INFO arks] content key invalid length".to_string(),
            "thread 'main' panicked at src/bin/main.rs:1:1".to_string(),
        ] {
            assert_eq!(scrub_line(&line), line);
        }
    }

    /// Runs in a child process: installs the scrubber on the real fd 2 and writes SDK
    /// lines the way `fpsLogError!` does.
    #[test]
    #[ignore = "child of scrubs_the_real_stderr"]
    fn scrub_child() {
        if std::env::var_os("ARKS_STDERR_SCRUB_CHILD").is_none() {
            return;
        }
        install().unwrap();
        eprintln!(
            "{}",
            sdk_line(
                -42585,
                &format!("fpssdk panic: x, panic input: {{\"content-key\":\"{KEY}\"}}")
            )
        );
        eprintln!("{}", sdk_line(-42583, "SPC not found"));
        // As main does on exit: the last line must not be lost
        eprintln!("last line before exit");
        finish();
        eprintln!("after finish");
    }

    #[test]
    fn scrubs_the_real_stderr() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "modules::stderr_scrub::tests::scrub_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ARKS_STDERR_SCRUB_CHILD", "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}");
        assert!(!stderr.contains(KEY), "{stderr}");
        assert!(
            stderr.contains("FP_ERRCODE=\"-42585\" [fpssdk message redacted"),
            "{stderr}"
        );
        assert!(stderr.contains("SPC not found"), "{stderr}");
        assert!(stderr.contains("last line before exit"), "{stderr}");
        assert!(stderr.contains("after finish"), "{stderr}");
    }
}
