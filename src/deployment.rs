use crate::{config::Target, util};
use anyhow::{Context, Result, ensure};
use duct::Expression;
use std::fmt::Write as _;
use std::{
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn path_arg(path: &Path) -> Result<String> {
    Ok(quote(path.to_str().context("non-UTF8 deployment path")?))
}

fn cmd_ssh(
    target: &Target,
    copy: bool,
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Expression> {
    let ssh = target.ssh.as_ref().context("missing SSH configuration")?;
    // Keep transport flags explicit: publication must be non-interactive and host-key pinned.
    let mut args: Vec<OsString> = [
        if copy { "-B" } else { "-T" }, // disable stdin processing for scp / allocate no TTY for ssh
        "-oBatchMode=yes",              // never prompt for credentials or confirmation
        "-oStrictHostKeyChecking=yes",  // accept only keys already trusted by the SSH configuration
        "-oConnectTimeout=10",          // bound a failed target connection
        "-oForwardAgent=no",            // do not expose the caller's agent
        "-oClearAllForwardings=yes",    // prevent configured forwarding from changing scope
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if let Some(port) = ssh.port {
        // select the configured SSH port
        args.push(if copy { "-P" } else { "-p" }.into());
        args.push(port.to_string().into());
    }
    args.extend(ssh.extra_args.iter().cloned().map(OsString::from));

    args.extend(arguments);
    Ok(duct::cmd(if copy { "scp" } else { "ssh" }, args))
}

fn run_shell(target: &Target, script: &str) -> Result<Vec<u8>> {
    let cmd = if let Some(ssh) = &target.ssh {
        cmd_ssh(target, false, [ssh.host.clone().into(), "sh -s".into()])?
    } else {
        duct::cmd("sh", ["-s"])
    };
    let script = format!("set -eu\n{script}\n");
    // Shell commands arrive on stdin, so the process arguments alone omit them.
    if log::log_enabled!(log::Level::Debug) {
        for line in script.lines() {
            log::debug!("Shell script for {}: {line}", target.name);
        }
    }
    util::command(&cmd, script.as_bytes(), Duration::from_secs(120))
}

/// Write bytes into a temporary file at target, colocated with the final file
fn stage_file(target: &Target, active: &Path, bytes: &[u8]) -> Result<PathBuf> {
    ensure!(
        bytes.len() as u64 <= util::MAX_FILE,
        "file exceeds deployment limit"
    );
    /*
    active:     /zones/example.com.zone
    local:      /tmp/dns-publish-AbC123
    temporary:  /zones/.example.com.zone.dns-publish-AbC123.tmp
     */
    // Write to local temporary file
    let mut local = tempfile::Builder::new().prefix("dns-publish-").tempfile()?;
    local.write_all(bytes)?;
    local.as_file().sync_all()?;
    let filename = active
        .file_name()
        .context("missing target filename")?
        .to_str()
        .context("non-UTF8 filename")?;
    let target_temp_path = active.with_file_name(format!(
        ".{filename}.{}.tmp",
        local.path().file_name().unwrap().to_str().unwrap()
    ));

    // Copy to local or remote locations
    let res_copy = if let Some(ssh) = &target.ssh {
        let cmd = cmd_ssh(
            target,
            true, // scp
            [
                "--".into(),                         // stop option parsing before the source path
                local.path().as_os_str().to_owned(), // src: fsynced local temporary file
                format!("{}:{}", ssh.host, target_temp_path.display()).into(), // dst
            ],
        )?;
        util::command(&cmd, &[], Duration::from_secs(120)).map(|_| ())
    } else {
        fs::copy(local.path(), &target_temp_path)
            .map(|_| ())
            .map_err(Into::into)
    };
    if let Err(error) = res_copy {
        cleanup(target, &target_temp_path);
        return Err(error);
    }
    Ok(target_temp_path)
}

fn cleanup(target: &Target, temp_file: &Path) {
    if let Ok(path) = path_arg(temp_file) {
        let _ = run_shell(target, &format!("rm -f -- {path}"));
    }
}

/// Install a zone file to a target
pub fn install(target: &Target, id: &str, contents: &str) -> Result<()> {
    const FILE_MODE: u32 = 0o644;
    let directory = path_arg(&target.directory)?;
    let active = target.directory.join(format!("{id}.zone"));
    let path = path_arg(&active)?;
    let wanted = contents.as_bytes();
    // Create target directories using rw-r-----
    let mut create = String::new();
    writeln!(create, "umask 027")?; // restrict new paths to the owner and its group
    writeln!(create, "mkdir -p -- {directory}")?; // create the zone directory
    run_shell(target, &create)?;
    // Read the active zone and its mode, treating an absent file as empty.
    let mut probe = String::new();
    writeln!(probe, "if test -e {path}; then")?; // an absent file is not an error
    writeln!(probe, "stat -c %a -- {path}")?; //   print the permission bits
    writeln!(probe, "cat -- {path}")?; //   print the live contents
    writeln!(probe, "fi")?;
    let current = run_shell(target, &probe)?;

    // Idempotency check for content and mode
    // Output from previous:
    // 644
    // (file contents)
    let (existing_mode, existing) = match current.iter().position(|b| *b == b'\n') {
        Some(split) => (
            u32::from_str_radix(std::str::from_utf8(&current[..split])?, 8)?,
            &current[split + 1..],
        ),
        None => (0, &current[..]),
    };
    if existing == wanted {
        if existing_mode == FILE_MODE {
            return Ok(());
        }
        let mut repair = String::new();
        writeln!(repair, "chmod {:o} -- {path}", FILE_MODE)?; // apply the documented mode
        writeln!(repair, "sync -f -- {path}")?; // flush the permission change
        run_shell(target, &repair)?;
        return Ok(());
    }

    // File changed.
    // Stage and rename so readers see only complete files.
    let temporary_path = stage_file(target, &active, wanted)?;
    let temporary = path_arg(&temporary_path)?;
    let hash = quote(&util::digest(wanted));
    let mut activate = String::new();
    writeln!(
        activate,
        "printf '%s  %s\\n' {hash} {temporary} | sha256sum --check --status"
    )?; // verify the upload
    writeln!(activate, "chmod {:o} -- {temporary}", FILE_MODE)?; // apply the documented mode
    writeln!(activate, "sync -f -- {temporary}")?; // flush the upload
    writeln!(activate, "mv -fT -- {temporary} {path}")?; // replace the live file atomically
    writeln!(activate, "sync -f -- {directory}")?; // flush the directory entry
    let result = run_shell(target, &activate);
    // Remove the uploaded temporary file, whether or not activation succeeded.
    cleanup(target, &temporary_path);
    result?;
    Ok(())
}
