mod config;
mod dialer;
mod listener;
mod proto;
mod stream;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{env, io, net, result};

use backoff::{ExponentialBackoff, ExponentialBackoffBuilder};
use capnp::message::Builder;
use capnp::serialize;
use clap::Parser;
use thiserror::Error;

use flume::{unbounded, Receiver, Sender};

use tokio::net::{TcpListener, TcpSocket};

use veilid_core::{
    CryptoKey, RoutingContext, SafetySelection, SafetySpec, Sequencing, VeilidAPIResult, DHTRecordDescriptor,
};
use veilid_core::{
    CryptoTyped, DHTSchema, DHTSchemaDFLT, Target, VeilidAPI, VeilidAPIError, VeilidUpdate,
    CRYPTO_KIND_VLD0,
};

use crate::dialer::Dialer;
use crate::listener::AppCallListener;
use crate::stream::AppCallStream;

#[derive(Debug)]
pub enum PipeSpec {
    Export {
        from_local: net::SocketAddr,
    },
    Import {
        from_remote: String,
        to_local: net::SocketAddr,
    },
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("not supported: {0}")]
    NotSupported(String),
    #[error("invalid socket address: {0}")]
    ParseAddr(#[from] net::AddrParseError),
    #[error("io error: {0}")]
    IO(#[from] io::Error),
    #[error("api error: {0}")]
    API(#[from] VeilidAPIError),
}

pub type Result<T> = result::Result<T, AppError>;

#[derive(Parser, Debug)]
#[command(name = "vldpipe")]
#[command(bin_name = "vldpipe")]
pub struct Cli {
    pub src: String,
    pub dst: Option<String>,

    #[arg(long)]
    pub app_dir: Option<String>,
}

impl Cli {
    pub fn app_dir(&self) -> String {
        match &self.app_dir {
            Some(app_dir) => app_dir.to_owned(),
            None => format!(
                "{}/{}",
                env::home_dir().unwrap_or(".".into()).to_string_lossy(),
                ".vldpipe"
            ),
        }
    }
}

impl TryInto<PipeSpec> for Cli {
    type Error = AppError;

    fn try_into(self) -> Result<PipeSpec> {
        match self.dst.as_ref() {
            None => Ok(PipeSpec::Export {
                from_local: net::SocketAddr::from_str(self.src.as_str())?,
            }),
            Some(dst) => Ok(PipeSpec::Import {
                from_remote: self.src.clone(),
                to_local: net::SocketAddr::from_str(dst)?,
            }),
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{}", e);
        std::process::exit(1)
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    let app_dir = cli.app_dir();

    // Create client api state change pipe
    let (node_sender, node_receiver): (
        Sender<veilid_core::VeilidUpdate>,
        Receiver<veilid_core::VeilidUpdate>,
    ) = unbounded();

    let key_pair = veilid_core::Crypto::generate_keypair(CRYPTO_KIND_VLD0)?;

    // Create VeilidCore setup
    let update_callback = Arc::new(move |change: veilid_core::VeilidUpdate| {
        let _ = node_sender.send(change);
    });
    let config_callback =
        Arc::new(move |key| config::config_callback(app_dir.clone(), key_pair, key));

    let api: veilid_core::VeilidAPI =
        veilid_core::api_startup(update_callback, config_callback).await?;
    api.attach().await?;

    eprintln!("waiting for network...");

    // Wait for network to be up
    loop {
        let res = node_receiver.recv_async().await;
        match res {
            Ok(VeilidUpdate::Attachment(attachment)) => {
                eprintln!("{:?}", attachment);
                if attachment.public_internet_ready {
                    break;
                }
            }
            Ok(VeilidUpdate::Config(_)) => {}
            Ok(VeilidUpdate::Log(_)) => {}
            Ok(VeilidUpdate::Network(_)) => {}
            Ok(u) => {
                eprintln!("{:?}", u);
            }
            Err(e) => {
                eprintln!("bad news bears {:?}", e);
            }
        };
    }

    let pipe_spec: PipeSpec = cli.try_into()?;
    match pipe_spec {
        PipeSpec::Export { from_local } => run_export(api, node_receiver, from_local).await,
        PipeSpec::Import {
            from_remote,
            to_local,
        } => run_import(api, node_receiver, from_remote, to_local).await,
    }
}

async fn run_import(
    api: VeilidAPI,
    node_receiver: Receiver<VeilidUpdate>,
    from_remote: String,
    to_local: SocketAddr,
) -> Result<()> {
    let local_ln = TcpListener::bind(to_local).await?;
    eprintln!("import: started local listener on {}", to_local);

    let routing_context = api.routing_context().with_custom_privacy(privacy())?;
    let dialer = Dialer::new(routing_context.clone(), node_receiver).await?;

    let remote_dht = open_dht_record(&routing_context, from_remote.to_owned()).await?;
    eprintln!("import: opened dht {:?}", remote_dht);
    
    let result: Result<()> = async {
        loop {
            let (local_stream, local_addr) = local_ln.accept().await?;
            eprintln!("import: accepted connection from {}", local_addr);

            let remote_stream = dialer.dial(remote_dht.clone()).await?;
            eprintln!(
                "import: dialed remote stream_id={:?}",
                remote_stream.stream_id()
            );
            tokio::spawn(forward(local_stream, remote_stream));
            eprintln!("import: started forward");
        }
    }
    .await;
    if let Err(e) = dialer.close().await {
        eprintln!("import: failed to close dialer: {:?}", e);
    }
    result
}

async fn run_export(
    api: VeilidAPI,
    node_receiver: Receiver<VeilidUpdate>,
    from_local: SocketAddr,
) -> Result<()> {
    // Veilid "bind()"
    // Create an in-bound route to handle new connections, like a port
    let (_inbound_key, ln_inbound_blob) = new_private_route(&api).await?;
    // Store its routing blob in DHT
    let routing_context = api.routing_context().with_custom_privacy(privacy())?;
    let ln_inbound_dht = routing_context
        .create_dht_record(DHTSchema::DFLT(DHTSchemaDFLT { o_cnt: 1 }), None)
        .await?;
    routing_context
        .set_dht_value(ln_inbound_dht.key().to_owned(), 0, ln_inbound_blob.clone())
        .await?;

    // Print the DHT key, this is what clients can "connect()" to
    eprintln!("listening on {}", ln_inbound_dht.key());

    let ln = AppCallListener::bind(routing_context, node_receiver, ln_inbound_dht).await?;
    let result = async {
        loop {
            let remote = ln.accept().await?;
            let socket = TcpSocket::new_v4()?;
            tokio::spawn(forward(socket.connect(from_local).await?, remote));
            eprintln!("export: starting forward");
        }
    }
    .await;
    if let Err(e) = ln.close().await {
        eprintln!("import: failed to close listener: {:?}", e);
    }
    result
}

async fn open_dht_record(
    routing_context: &RoutingContext,
    from_remote: String,
) -> VeilidAPIResult<DHTRecordDescriptor> {
    backoff::future::retry_notify(
        ExponentialBackoff::default(),
        || async {
            Ok(routing_context
                .open_dht_record(CryptoTyped::from_str(from_remote.as_str())?, None)
                .await?)
        },
        |e, dur| {
            eprintln!("get_remote_route failed: {:?} after {:?}", e, dur);
        },
    )
    .await
}

async fn forward(
    mut local_stream: tokio::net::TcpStream,
    remote_stream: AppCallStream,
) -> Result<()> {
    let stream_id = remote_stream.stream_id();
    eprintln!("{} forward start", stream_id);
    let (mut local_read, mut local_write) = local_stream.split();
    let (mut remote_read, mut remote_write) = tokio::io::split(remote_stream);
    match tokio::try_join!(
        async { tokio::io::copy(&mut remote_read, &mut local_write).await },
        async { tokio::io::copy(&mut local_read, &mut remote_write).await },
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(AppError::IO(io::Error::new(io::ErrorKind::Other, e))),
    }
}

async fn new_private_route(api: &VeilidAPI) -> VeilidAPIResult<(CryptoKey, Vec<u8>)> {
    backoff::future::retry_notify(
        ExponentialBackoff::default(),
        || async { Ok(api.new_private_route().await?) },
        |e, dur| {
            eprintln!("new_private_route failed: {:?} after {:?}", e, dur);
        },
    )
    .await
}

fn app_call_backoff() -> ExponentialBackoff {
    ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_millis(500))
        .with_max_elapsed_time(Some(Duration::from_secs(15)))
        .build()
}

async fn app_call(
    routing_context: &RoutingContext,
    target: Target,
    message: Vec<u8>,
) -> VeilidAPIResult<Vec<u8>> {
    backoff::future::retry_notify(
        app_call_backoff(),
        || async {
            Ok(routing_context
                .app_call(target.clone(), message.clone())
                .await?)
        },
        |e, dur| {
            eprintln!("app_call failed: {:?} after {:?}", e, dur);
        },
    )
    .await
}

fn privacy() -> SafetySelection {
    SafetySelection::Safe(SafetySpec {
        sequencing: Sequencing::EnsureOrdered,
        stability: veilid_core::Stability::LowLatency,
        preferred_route: None,
        hop_count: 1,
    })
}
