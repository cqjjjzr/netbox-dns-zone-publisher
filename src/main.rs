use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use netbox_dns_zone_publisher::{config::Config, publisher, util::StateLock};
use std::{io::Write, path::PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Command line: an optional config path and the requested command.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Collect,
    Publish,
}

fn main() {
    let journal = std::env::var_os("JOURNAL_STREAM").is_some();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .format(move |buffer, record| {
            if journal {
                let priority = match record.level() {
                    log::Level::Error => 3,
                    log::Level::Warn => 4,
                    log::Level::Info => 6,
                    log::Level::Debug | log::Level::Trace => 7,
                };
                writeln!(buffer, "<{priority}>{}", record.args())
            } else {
                writeln!(
                    buffer,
                    "[{}] [{}] {}",
                    OffsetDateTime::now_utc()
                        .format(&Rfc3339)
                        .unwrap_or_else(|_| "?".to_string()),
                    record.level(),
                    record.args()
                )
            }
        })
        .init();
    let exec_result: Result<()> = (|| {
        let cli = Cli::parse();
        let config = Config::read(&cli.config.context("--config is required")?)?;
        let _lock = StateLock::try_lock(&config.state_dir)?;
        match cli.command {
            Commands::Collect => publisher::collect(&config)?,
            Commands::Publish => publisher::publish(&config)?,
        }
        Ok(())
    })();
    if let Err(e) = exec_result {
        log::error!("{e:#}");
        std::process::exit(1);
    }
}
