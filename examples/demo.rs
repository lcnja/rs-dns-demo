use anyhow::Result;
use clap;
use clap::crate_name;
use clap::value_t_or_exit;
use env_logger::Env;
use log::debug;
use rs_dns_demo::dns::DNSServer;

use std::env;
use std::io::Write;
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace"))
        .format_timestamp(None)
        .format(|buf, record| {
            writeln!(
                buf,
                "{:<5}\t[{}:{}]\n\t\t{}\n",
                record.level(),
                record.file().unwrap(),
                record.line().unwrap_or(0),
                &record.args()
            )
        })
        .init();

    let matches = clap::App::new(crate_name!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .author(clap::crate_authors!())
        .arg(
            clap::Arg::with_name("name")
                .short("n")
                .long("name")
                .env("DNS_ID")
                .takes_value(true)
                .default_value("myself.local"),
        )
        .arg(
            clap::Arg::with_name("addr")
                .short("a")
                .long("addr")
                .env("DNS_ADDR")
                .takes_value(true)
                .default_value("127.0.0.1"),
        )
        .arg(
            clap::Arg::with_name("port")
                .short("p")
                .long("port")
                .env("DNS_PORT")
                .takes_value(true)
                .default_value("53"),
        )
        .arg(
            clap::Arg::with_name("forwarder")
                .short("f")
                .long("forwarder")
                .env("DNS_FORWARDER")
                .takes_value(true)
                .default_value("1.1.1.1"),
        )
        .arg(
            clap::Arg::with_name("forwarder_port")
                .long("forwarder_port")
                .env("DNS_FORWARDER_PORT")
                .takes_value(true)
                .default_value("53"),
        )
        .get_matches();

    let dns_name = clap::value_t_or_exit!(matches, "name", String);
    let addr = clap::value_t_or_exit!(matches, "addr", std::net::Ipv4Addr);
    let port = clap::value_t_or_exit!(matches, "port", u32);
    let forwarder = clap::value_t_or_exit!(matches, "forwarder", Ipv4Addr);
    let forwarder_port = clap::value_t_or_exit!(matches, "forwarder_port", u16);

    debug!(
        "Start DNS server with name {} at {:?}:{}, forwarder: {}:{}",
        dns_name, addr, port, forwarder, forwarder_port
    );

    DNSServer::new(addr, port, dns_name.as_str(), forwarder, forwarder_port)
        .await?
        .start()
        .await?;

    Ok(())
}
