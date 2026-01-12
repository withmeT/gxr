use clap::{Parser, Subcommand};
use gxr::commands::{net, pentest};
use std::process;

#[derive(Parser, Debug)]
#[command(name = "gxtools")]
#[command(version, about = "GX安全工具箱 - 网络测试、渗透测试、等保核查工具集", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 网络测试模块
    Net {
        #[command(subcommand)]
        subcommand: NetCommands,
    },
    /// 渗透测试模块
    Pentest {
        #[command(subcommand)]
        subcommand: PentestCommands,
    },
}

#[derive(Subcommand, Debug)]
enum NetCommands {
    /// Ping主机存活扫描
    #[command(name = "ping")]
    Ping(net::ping::PingArgs),
}

#[derive(Subcommand, Debug)]
enum PentestCommands {
    /// 端口扫描
    #[command(name = "portscan")]
    PortScan(pentest::portscan::PortScanArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Net { subcommand } => handle_net_command(subcommand).await,
        Commands::Pentest { subcommand } => handle_pentest_command(subcommand).await,
    };

    if let Err(e) = result {
        eprintln!("❌ 执行失败: {}", e);
        process::exit(1);
    }
}

async fn handle_net_command(
    cmd: NetCommands,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        NetCommands::Ping(args) => net::ping::run(&args).await,
    }
}

async fn handle_pentest_command(
    cmd: PentestCommands,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        PentestCommands::PortScan(args) => pentest::portscan::run(&args).await,
    }
}
