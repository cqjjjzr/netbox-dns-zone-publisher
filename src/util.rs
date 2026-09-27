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
        fs::create_dir_all(root)
            .with_context(|| format!("create state directory {}", root.display()))?;
        let lock_path = root.join("lock");
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open state lock {} for writing", lock_path.display()))?;
        f.try_lock()
            .map_err(|error| match error {
                TryLockError::WouldBlock => anyhow!("another writer holds the state lock"),
                TryLockError::Error(error) => error.into(),
            })
            .with_context(|| format!("acquire state lock {}", lock_path.display()))?;
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
    atomic_write_inner(path, bytes, mode)
        .with_context(|| format!("atomically write {}", path.display()))
}

fn atomic_write_inner(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("missing parent directory")?;
    fs::create_dir_all(parent).context("create parent directory")?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).context("create temporary file")?;
    use std::os::unix::fs::PermissionsExt;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))
        .context("set temporary file permissions")?;
    temp.write_all(bytes).context("write temporary file")?;
    temp.as_file().sync_all().context("sync temporary file")?;
    temp.persist(path)
        .map_err(|e| e.error)
        .context("persist temporary file")?;
    File::open(parent)
        .context("open parent directory for sync")?
        .sync_all()
        .context("sync parent directory")?;
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
    log::debug!("Command stdin:\n{}", String::from_utf8_lossy(input));
    let handle = expr
        .start()
        .with_context(|| format!("start subprocess {cmd:?}"))?;

    let timed_out = handle
        .wait_timeout(timeout)
        .with_context(|| format!("wait for subprocess {cmd:?}"))?
        .is_none();
    if timed_out {
        handle
            .kill()
            .with_context(|| format!("kill timed-out subprocess {cmd:?}"))?;
    }

    let mut output = handle
        .into_output()
        .with_context(|| format!("capture subprocess output {cmd:?}"))?;
    log::debug!(
        "Command completed: {cmd:?}\nstatus: {}; timed out: {timed_out}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if timed_out || !output.status.success() {
        output.stdout.truncate(1_048_576);
        output.stderr.truncate(1_048_576);
        let reason = if timed_out {
            "subprocess timed out".to_owned()
        } else {
            format!("subprocess failed ({})", output.status)
        };
        bail!(
            "{reason}: {cmd:?}\nstdout: \n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(output.stdout)
}
