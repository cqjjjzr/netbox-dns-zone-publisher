use netbox_dns_zone_publisher::util::{self, StateLock};
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    time::Duration,
};

#[test]
fn bounded_reads_accept_the_boundary_and_reject_one_extra_byte() {
    assert_eq!(
        util::bounded_read_with_limit(&b"abc"[..], 3).unwrap(),
        b"abc"
    );
    assert!(
        util::bounded_read_with_limit(&b"abcd"[..], 3)
            .unwrap_err()
            .to_string()
            .contains("size limit")
    );
    assert_eq!(util::bounded_read_with_limit(io::empty(), 0).unwrap(), b"");
    struct BrokenReader;
    impl Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failed"))
        }
    }
    assert!(
        util::bounded_read_with_limit(BrokenReader, 3)
            .unwrap_err()
            .to_string()
            .contains("read failed")
    );
}

#[test]
fn atomic_write_replaces_contents_and_applies_requested_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nested/state.json");
    util::atomic_write(&path, b"old").unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    util::atomic_write_with_mode(&path, b"replacement", 0o640).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
}

#[test]
fn state_lock_fences_a_second_writer_and_releases_on_drop() {
    let temp = tempfile::tempdir().unwrap();
    let first = StateLock::try_lock(temp.path()).unwrap();
    let error = StateLock::try_lock(temp.path())
        .err()
        .expect("second writer must fail");
    assert!(error.to_string().contains("another writer"));
    drop(first);
    StateLock::try_lock(temp.path()).unwrap();
}

#[test]
fn subprocess_returns_stdout_and_includes_both_streams_on_failure() {
    let output = util::command(
        &duct::cmd("cat", [] as [&str; 0]),
        b"input",
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(output, b"input");
    let error = util::command(
        &duct::cmd(
            "sh",
            ["-c", "printf diagnostic; printf problem >&2; exit 7"],
        ),
        b"",
        Duration::from_secs(5),
    )
    .unwrap_err()
    .to_string();
    for expected in ["subprocess failed", "7", "diagnostic", "problem"] {
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn subprocess_timeout_kills_and_reports_the_child() {
    // exec leaves no grandchild holding a captured pipe open after the kill.
    let error = util::command(
        &duct::cmd("sh", ["-c", "exec sleep 30"]),
        b"",
        Duration::from_millis(20),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("subprocess timed out"), "{error}");
}
