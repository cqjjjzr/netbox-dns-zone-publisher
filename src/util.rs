use anyhow::{Context, Result, anyhow, bail, ensure};
use duct::Expression;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{Read, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub const MAX_FILE: u64 = 64 * 1024 * 1024;
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_secs()
}

/// An exclusive advisory lock fencing writers out of the state directory.
pub struct StateLock(File);
impl StateLock {
    pub fn try_lock(root: &Path) -> Result<StateLock> {
        fs::create_dir_all(root)?;
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("lock"))?;
        f.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => anyhow!("another writer holds the state lock"),
            TryLockError::Error(error) => error.into(),
        })?;
        Ok(StateLock(f))
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // A concurrently spawned child can inherit the descriptor until exec.
        // End the lock at this scope boundary, independently of inherited copies.
        let _ = self.0.unlock();
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write_with_mode(path, bytes, 0o600)
}

pub fn atomic_write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("missing parent directory")?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    use std::os::unix::fs::PermissionsExt;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn bounded_read(reader: impl Read) -> Result<Vec<u8>> {
    bounded_read_with_limit(reader, MAX_FILE)
}

pub fn bounded_read_with_limit(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "input exceeds size limit");
    Ok(bytes)
}

pub fn command(cmd: &Expression, input: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    // Use duct-provided captures. No need to use file backed pipes since called tools are trusted.
    let expr = cmd
        .stdin_bytes(input)
        .stdout_capture()
        .stderr_capture()
        // We want to inspect status/stderr ourselves.
        .unchecked();

    log::debug!("Executing command: {cmd:?}");
    let handle = expr.start().context("start subprocess")?;

    let timed_out = handle.wait_timeout(timeout)?.is_none();
    if timed_out {
        handle.kill().context("kill timed-out subprocess")?;
    }

    let mut output = handle.into_output()?;
    if timed_out || !output.status.success() {
        output.stdout.truncate(1_048_576);
        output.stderr.truncate(1_048_576);
        let reason = if timed_out {
            "subprocess timed out".to_owned()
        } else {
            format!("subprocess failed ({})", output.status)
        };
        bail!(
            "{reason}: \nstdout: \n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(output.stdout)
}
