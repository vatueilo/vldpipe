mod config;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{env, io, net, result};

use clap::Parser;
use thiserror::Error;

use flume::{unbounded, Receiver, Sender};

use tokio::net::{TcpListener, TcpSocket};
use tokio::select;
use veilid_core::{AttachmentState, RoutingContext, Sequencing};
use veilid_core::{
    CryptoTyped, DHTSchema, DHTSchemaDFLT, Target, VeilidAPI, VeilidAPIError, VeilidUpdate,
    CRYPTO_KIND_VLD0,
};

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
    let key_pair = veilid_core::Crypto::generate_keypair(CRYPTO_KIND_VLD0)?;

    // Create client api state change pipe
    let (sender, receiver): (
        Sender<veilid_core::VeilidUpdate>,
        Receiver<veilid_core::VeilidUpdate>,
    ) = unbounded();

    // Create VeilidCore setup
    let node_sender = sender.clone();
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
        select! {
            res = receiver.recv_async() => {
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
                }
            }
        };
    }

    let node_id = api.routing_table()?.node_id(CRYPTO_KIND_VLD0);
    eprintln!("node id: {}", node_id);

    let pipe_spec: PipeSpec = cli.try_into()?;
    match pipe_spec {
        PipeSpec::Export { from_local } => {
            // "bind()"
            let (_ln_inbound_key, ln_inbound_blob) = api.new_private_route().await?;
            let routing_context = api
                .routing_context()
                .with_sequencing(Sequencing::EnsureOrdered)
                .with_privacy()?;
            let ln_inbound_dht = routing_context
                .create_dht_record(DHTSchema::DFLT(DHTSchemaDFLT { o_cnt: 1 }), None)
                .await?;
            routing_context
                .set_dht_value(ln_inbound_dht.key().to_owned(), 0, ln_inbound_blob)
                .await?;
            routing_context
                .close_dht_record(ln_inbound_dht.key().to_owned())
                .await?;
            eprintln!("listening on {}", ln_inbound_dht.key());
            loop {
                match receiver.recv_async().await {
                    Ok(VeilidUpdate::AppCall(call)) => {
                        // "accept()" with privacy:
                        // read the remote's private route, reply with ours
                        eprintln!("accept: {:?}", call);
                        let conn_outbound_target = Target::PrivateRoute(
                            api.import_remote_private_route(call.message().to_vec())?,
                        );
                        eprintln!(
                            "imported connection outbound target {:?}",
                            conn_outbound_target
                        );
                        // creating inbound private route for connection responses
                        let (conn_inbound_key, conn_inbound_blob) = api.new_private_route().await?;
                        eprintln!("created connection inbound route {:?}", conn_inbound_key);
                        eprintln!("starting forward");
                        let socket = TcpSocket::new_v4()?;
                        tokio::spawn(export_forward(
                            conn_outbound_target.clone(),
                            socket.connect(from_local).await?,
                            routing_context.clone(),
                            receiver.clone(),
                        ));
                        eprintln!("replied to caller");
                        api.app_call_reply(call.id(), conn_inbound_blob).await?;
                    }
                    Ok(VeilidUpdate::Shutdown) => {
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("recv failed, {}", e);
                    }
                };
            }
        }
        PipeSpec::Import {
            from_remote,
            ref to_local,
        } => {
            // TODO: get the private route blob from DHT, import it as listener_target
            let remote_target: Target;
            loop {
                match get_remote_route(api.clone(), from_remote.to_owned()).await {
                    Ok(target) => {
                        remote_target = target;
                        break;
                    }
                    Err(e) => {
                        eprintln!("failed to get remote route: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
            let local_ln = TcpListener::bind(to_local).await?;
            eprintln!("started local listener on {}", to_local);

            'outer: loop {
                // Accept local TCP connection
                let (local_stream, _local_addr) = local_ln.accept().await?;

                // Connect to remote target
                let (conn_inbound_addr, conn_inbound_blob) = api.new_private_route().await?;
                eprintln!(
                    "created new inbound connection route {:?}",
                    conn_inbound_addr
                );
                let routing_context = api
                    .routing_context()
                    .with_sequencing(Sequencing::EnsureOrdered)
                    .with_privacy()?;
                eprintln!("calling remote for outbound target");
                let conn_outbound_blob: Vec<u8>;
                loop {
                    match routing_context
                        .app_call(remote_target.clone(), conn_inbound_blob.clone())
                        .await
                    {
                        Ok(blob) => {
                            conn_outbound_blob = blob;
                            break;
                        }
                        Err(VeilidAPIError::InvalidTarget) => {
                            eprintln!("invalid target");
                            continue 'outer;
                        }
                        Err(e) => {
                            eprintln!("failed to get outbound target: {:?}", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    }
                }
                // make rpc call to listener_target, get remote private route, import as conn_target
                let conn_outbound_target =
                    Target::PrivateRoute(api.import_remote_private_route(conn_outbound_blob)?);
                eprintln!("got outbound connection target {:?}", conn_outbound_target);
                eprintln!("starting forward");
                tokio::spawn(export_forward(
                    conn_outbound_target.clone(),
                    local_stream,
                    routing_context.clone(),
                    receiver.clone(),
                ));
            }
        }
    };

    api.detach().await?;
    api.shutdown().await;
    Ok(())
}

async fn get_remote_route(api: VeilidAPI, from_remote: String) -> Result<Target> {
    let routing_context = api
        .routing_context()
        .with_sequencing(Sequencing::EnsureOrdered)
        .with_privacy()?;
    let remote_dht = routing_context
        .open_dht_record(CryptoTyped::from_str(from_remote.as_str())?, None)
        .await?;
    let remote_entry = routing_context
        .get_dht_value(remote_dht.key().to_owned(), 0, true)
        .await?;
    let remote_blob = remote_entry.unwrap().data().to_vec();
    Ok(Target::PrivateRoute(
        api.import_remote_private_route(remote_blob)?,
    ))
}

async fn export_forward(
    target: Target,
    mut local_stream: tokio::net::TcpStream,
    routing_context: RoutingContext,
    receiver: Receiver<VeilidUpdate>,
) -> Result<()> {
    let (local_read, local_write) = local_stream.split();
    let mut rd_buf = vec![0u8; 32768];
    loop {
        select! {
            ready = local_read.readable() => {
                match ready {
                    Ok(_) => {
                        match local_read.try_read(&mut rd_buf) {
                            Ok(n) => {
                                eprintln!("read {} bytes from local stream", n);
                                loop {
                                    match routing_context.app_message(target.clone(), rd_buf[..n].to_vec()).await {
                                        Ok(_) => break,
                                        Err(VeilidAPIError::InvalidTarget) => return Err(AppError::API(VeilidAPIError::InvalidTarget)),
                                        Err(e) => {
                                            eprintln!("remote send failed: {:?}", e);
                                        }
                                    }
                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                }
                                eprintln!("remote send ok");
                            },
                            Err(e) => {
                                if e.kind() != io::ErrorKind::WouldBlock {
                                    eprintln!("local read failed: {:?}", e);
                                    return Err(AppError::IO(e));
                                }
                            }
                        };
                    }
                    Err(e) => {
                        eprintln!("readable: {:?}", e);
                        return Err(AppError::IO(e));
                    }
                }
            }
            node_res = receiver.recv_async() => {
                match node_res {
                    Ok(VeilidUpdate::AppMessage(msg)) => {
                        eprintln!("writing message from remote {:?}", msg);
                        // TODO: error handling, deal with partial writes, blah blah
                        let mut wr = 0;
                        while wr < msg.message.len() {
                            local_write.writable().await?;
                            match local_write.try_write(&msg.message[wr..]) {
                                Ok(n) => {
                                    wr += n
                                }
                                Err(e) => {
                                    if e.kind() != io::ErrorKind::WouldBlock {
                                        eprintln!("failed to write message from remote: {:?}", e);
                                        return Err(AppError::IO(e));
                                    }
                                }
                            }
                            eprintln!("wrote {} of {}", wr, msg.message.len());
                        }
                    }
                    Ok(VeilidUpdate::Shutdown) => {
                        eprintln!("shutdown received");
                        return Err(AppError::API(VeilidAPIError::Shutdown));
                    }
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
        };
    }
}
