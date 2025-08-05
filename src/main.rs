use clap::{Parser, Subcommand};
use std::io::Write;

mod config;
mod vpn;
mod ssh;
mod pass;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, global = true, help = "Enable verbose output")]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Vpn(vpn::VpnArgs),
    SshKey(ssh::SshArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .format(|buf, record| {
            writeln!(buf, "{}", record.args())
        })
        .init();

    let cli = Cli::parse();

    let config = config::Config::load()?;

    if cli.verbose {
        println!("Verbose output ...");
    }

    match &cli.command {
        Commands::Vpn(args) => vpn::run(args, &config.vpn).await?,
        Commands::SshKey(args) => ssh::run(args, &config.ssh_keys).await?,
    }

    Ok(())
}
