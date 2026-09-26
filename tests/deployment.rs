use netbox_dns_zone_publisher::{config::Target, deployment};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

#[test]
fn local_install_handles_shell_characters_and_repairs_mode_without_replacing_content() {
    let root = tempfile::tempdir().unwrap();
    let target = Target {
        name: "local".into(),
        directory: root.path().join("zones ' with $characters;"),
        ssh: None,
    };
    deployment::install(&target, "example.com", "zone bytes\n").unwrap();
    let active = target.directory.join("example.com.zone");
    let inode = fs::metadata(&active).unwrap().ino();
    fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
    deployment::install(&target, "example.com", "zone bytes\n").unwrap();
    assert_eq!(
        fs::metadata(&active).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(fs::metadata(&active).unwrap().ino(), inode);
    deployment::install(&target, "example.com", "updated bytes\n").unwrap();
    assert_eq!(fs::read(&active).unwrap(), b"updated bytes\n");
    assert_ne!(fs::metadata(&active).unwrap().ino(), inode);
    assert_eq!(
        fs::read_dir(&target.directory).unwrap().count(),
        1,
        "staging files must be cleaned up"
    );
}

#[test]
fn failed_probe_preserves_the_existing_destination_without_staging() {
    let root = tempfile::tempdir().unwrap();
    let target = Target {
        name: "local".into(),
        directory: root.path().join("zones"),
        ssh: None,
    };
    // A directory at the final path makes probing fail before installation.
    let active = target.directory.join("example.com.zone");
    fs::create_dir_all(&active).unwrap();
    fs::write(active.join("keep"), "sentinel").unwrap();
    assert!(deployment::install(&target, "example.com", "new bytes").is_err());
    assert_eq!(fs::read(active.join("keep")).unwrap(), b"sentinel");
    assert_eq!(fs::read_dir(&target.directory).unwrap().count(), 1);
}
