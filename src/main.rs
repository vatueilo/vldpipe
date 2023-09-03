mod config;
mod proto;
mod stream;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{env, io, net, result};

use backoff::{ExponentialBackoff, ExponentialBackoffBuilder};
use capnp::message::{Builder, ReaderOptions};
use capnp::serialize;
use clap::Parser;
use thiserror::Error;

use flume::{unbounded, Receiver, Sender};

use tokio::net::{TcpListener, TcpSocket};
use tokio::select;
use veilid_core::{
    CryptoKey, RoutingContext, SafetySelection, SafetySpec, Sequencing, VeilidAPIResult, Encodable, KeyPair, FourCC,
};
use veilid_core::{
    CryptoTyped, DHTSchema, DHTSchemaDFLT, Target, VeilidAPI, VeilidAPIError, VeilidUpdate,
    CRYPTO_KIND_VLD0,
};

use crate::stream::VeilidStream;

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
    let mut fwd_senders = HashMap::new();
    let mut fwd_handles = HashMap::new();

    // get the private route blob from DHT, import it as listener_target
    let remote_target = get_remote_route(api.clone(), from_remote.to_owned()).await?;

    let local_ln = TcpListener::bind(to_local).await?;
    eprintln!("import: started local listener on {}", to_local);
    let (conn_inbound_addr, conn_inbound_blob) = new_private_route(&api).await?;
    eprintln!(
        "import: created new inbound connection route {:?}",
        conn_inbound_addr
    );

    loop {
        select! {
            // Accept local TCP connection
            accept_res = local_ln.accept() => {
                match accept_res {
                    Ok((local_stream, local_addr)) => {
                        eprintln!("import: accepted connection from {}", local_addr);
                        // Connect to remote target
                        let routing_context = api
                            .routing_context()
                            .with_custom_privacy(privacy())?;
                        eprintln!("import: calling remote for outbound target");
                        let fwd_id: u64;
                        let conn_outbound_target: Target;
                        let connect_msg = new_connect_proto(0, &conn_inbound_blob);

                        // Veilid "connect()"
                        match app_call(&routing_context, remote_target.clone(), connect_msg).await {
                            Ok(resp) => {
                                let reader =
                                    serialize::read_message(resp.as_slice(), ReaderOptions::new())
                                        .unwrap();
                                let call = reader.get_root::<proto::call::Reader>().unwrap();

                                fwd_id = call.get_id();
                                let conn_outbound_blob = match call.which() {
                                    Ok(proto::call::Which::Route(Ok(route))) => route.to_owned(),
                                    Ok(_) => {
                                        eprintln!("import: invalid route response: {:?}", call);
                                        continue;
                                    }
                                    Err(e) => {
                                        eprintln!("import: invalid route response: {:?}", e);
                                        continue;
                                    }
                                };
                                conn_outbound_target = if let Ok(target_key) = api.import_remote_private_route(conn_outbound_blob) {
                                    Target::PrivateRoute(target_key)
                                } else {
                                    eprintln!("import: invalid target key");
                                    continue;
                                }
                            }
                            Err(VeilidAPIError::InvalidTarget) => {
                                eprintln!("import: invalid target");
                                continue;
                            }
                            Err(e) => {
                                eprintln!("import: failed to connect: {:?}", e);
                                continue;
                            }
                        }

                        // Create a sender / receiver for the forward
                        let (fwd_sender, fwd_receiver): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
                        fwd_senders.insert(fwd_id, fwd_sender);

                        // make rpc call to listener_target, get remote private route, import as conn_target
                        //let conn_outbound_target =
                        //    Target::PrivateRoute(api.import_remote_private_route(conn_outbound_blob)?);
                        //eprintln!("got outbound connection target {:?}", conn_outbound_target);
                        eprintln!("import: starting forward for {}", fwd_id);
                        let remote_stream = VeilidStream::new(fwd_id, routing_context, conn_outbound_target, fwd_receiver);
                        fwd_handles.insert(fwd_id, tokio::spawn(export_forward(local_stream, remote_stream)));
                        eprintln!("import: forward started for {}", fwd_id);
                    }
                    Err(e) => {
                        return Err(AppError::IO(e))
                    }
                }
            }
            node_res = node_receiver.recv_async() => {
                match node_res {
                    Ok(VeilidUpdate::AppCall(app_call)) => {
                        let reader = match serialize::read_message(
                            app_call.message(),
                            ReaderOptions::new(),
                        ) {
                            Ok(m) => m,
                            Err(e) => {
                                eprintln!("import: malformed message: {:?}", e);
                                continue
                            }
                        };
                        let call = match reader.get_root::<proto::call::Reader>() {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("import: failed to decode message: {:?}", e);
                                continue
                            }
                        };
                        eprintln!("import: got app_call {:?}", call);
                        let payload = match call.which() {
                            Ok(proto::call::Which::Payload(Ok(p))) => p,
                            Ok(_) => {
                                eprintln!("import: invalid call: {:?}", call);
                                continue
                            }
                            Err(e) => {
                                eprintln!("import: invalid call: {:?}", e);
                                continue
                            }
                        };

                        // route message to the right forward
                        let fwd_id: u64 = call.get_id();
                        match fwd_senders.get(&fwd_id) {
                            Some(fwd_sender) => {
                                if let Err(_) =
                                    fwd_sender.send(payload.to_vec())
                                {
                                    eprintln!("import: forward is gone, removing sender");
                                    fwd_senders.remove(&fwd_id);
                                    if let Some(handle) = fwd_handles.remove(&fwd_id) {
                                        handle.abort();
                                        let _ = handle.await;
                                    }
                                    continue
                                } else {
                                    eprintln!("import: sent payload to forwarding stream {}", fwd_id);
                                }
                            }
                            None => {
                                eprintln!("import: no such forward {}", fwd_id);
                            }
                        }

                        match api.app_call_reply(app_call.id(), stream::new_payload_proto(fwd_id, &[])).await {
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("import: app_call_reply for {} failed: {:?}",fwd_id, e);
                                eprintln!("import: removing sender for: {}", fwd_id);
                                fwd_senders.remove(&fwd_id);
                                if let Some(handle) = fwd_handles.remove(&fwd_id) {
                                    handle.abort();
                                    let _ = handle.await;
                                }
                                continue
                            }
                        };
                        eprintln!("import: handled app_call for {}", fwd_id);
                    }
                    Ok(VeilidUpdate::Shutdown) => {
                        eprintln!("import: shutdown received");
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("recv failed, {}", e);
                        break;
                    }
                }
            }
        };
    }
    eprintln!("import loop ended");
    Ok(())
}

async fn run_export(
    api: VeilidAPI,
    node_receiver: Receiver<VeilidUpdate>,
    from_local: SocketAddr,
) -> Result<()> {
    let mut fwd_map = HashMap::new();

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

    let mut refresh_dht_interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        select! {
            node_res = node_receiver.recv_async() => {
                match node_res {
                    Ok(VeilidUpdate::AppCall(app_call)) => {
                        let reader = serialize::read_message(app_call.message(), ReaderOptions::new()).unwrap();
                        let conn = reader.get_root::<proto::call::Reader>().unwrap();
                        eprintln!("export: got app_call {:?}", conn);
                        match conn.which() {
                            Ok(proto::call::Which::Route(Ok(route))) => {
                                // "accept()" with privacy, build a "socket pair"
                                //
                                // write-side (outbound): import the remote's private route to send responses to
                                // read-side (inbound): create a private route and reply with it, and the "socket" id
                                //
                                // For now we'll abuse the RPC call_id for this id out
                                // of laziness but this might not be secure, think about
                                // TCP sequence numbers :)
                                eprintln!("export: accept: {:?}", app_call);
                                let call_id: u64 = app_call.id().into();
                                let conn_outbound_target =
                                    Target::PrivateRoute(api.import_remote_private_route(route.to_vec())?);
                                eprintln!(
                                    "export: {} imported connection outbound target {:?}",
                                    call_id,
                                    conn_outbound_target
                                );

                                // creating inbound private route for connection responses
                                //let (conn_inbound_key, conn_inbound_blob) = new_private_route(&api).await?;
                                //eprintln!("export: {} created connection inbound route {:?}", call_id, conn_inbound_key);

                                eprintln!("export: {} starting forward", call_id);
                                let socket = TcpSocket::new_v4()?;

                                // Create a sender / receiver for the forward
                                let (fwd_sender, fwd_receiver): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
                                    unbounded();
                                fwd_map.insert(call_id, fwd_sender);

                                let remote_stream = VeilidStream::new(
                                    call_id, routing_context.clone(), conn_outbound_target, fwd_receiver);
                                tokio::spawn(export_forward(
                                    socket.connect(from_local).await?,
                                    remote_stream,
                                ));
                                eprintln!("export: {} started forward", call_id);

                                // TODO: possible data race here if the forward doesn't start selecting in time for the
                                // remote to start sending messages.

                                let connect_reply = new_connect_proto(call_id, &ln_inbound_blob);
                                match api.app_call_reply(app_call.id(), connect_reply).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        eprintln!("export: app_call_reply for {} failed: {:?}",call_id, e);
                                        eprintln!("export: removing sender for: {}", call_id);
                                        fwd_map.remove(&call_id);
                                    }
                                }
                                eprintln!("replied to caller");
                            }
                            Ok(proto::call::Which::Payload(Ok(payload))) => {
                                // decode call id out of message
                                // TODO: ignore malformed messages, we'll just panic for now

                                // route message to the right forward
                                let fwd_id: u64 = conn.get_id().into();
                                match fwd_map.get(&fwd_id) {
                                    Some(fwd_sender) => {
                                        if let Err(_) = fwd_sender.send(payload.to_vec()) {
                                            eprintln!("export: forward {} is gone, removing sender", fwd_id);
                                            fwd_map.remove(&fwd_id);
                                            break;
                                        }
                                        eprintln!("export: sent payload to forwarding stream {}", fwd_id);
                                    }
                                    None => {
                                        eprintln!("export: no matching forward for stream {}", fwd_id);
                                    }
                                }

                                match api.app_call_reply(app_call.id(), stream::new_payload_proto(fwd_id, &[])).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        eprintln!("export: app_call_reply for {} failed: {:?}",fwd_id, e);
                                        eprintln!("export: removing sender for: {}", fwd_id);
                                        fwd_map.remove(&fwd_id);
                                    }
                                };
                            }
                            _ => {
                                eprintln!("export: invalid call");
                            }
                        }
                    }
                    Ok(VeilidUpdate::Shutdown) => {
                        eprintln!("export: shutdown received");
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("export: recv failed, {}", e);
                        break;
                    }
                }
            }
            /*
            _ = refresh_dht_interval.tick() => {
                if let Err(e) = routing_context
                    .set_dht_value(ln_inbound_dht.key().to_owned(), 0, ln_inbound_blob.clone())
                    .await {
                        eprintln!("failed to re-notify dht key: {:?}", e);
                    } else {
                        eprintln!("refreshed dht");
                    }
            }
            */
        }
    }
    eprintln!("export loop ended");
    Ok(())
}

async fn get_remote_route(api: VeilidAPI, from_remote: String) -> VeilidAPIResult<Target> {
    backoff::future::retry_notify(
        ExponentialBackoff::default(),
        || async {
            let routing_context = api.routing_context().with_custom_privacy(privacy())?;
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
        },
        |e, dur| {
            eprintln!("get_remote_route failed: {:?} after {:?}", e, dur);
        },
    )
    .await
}

async fn export_forward(
    mut local_stream: tokio::net::TcpStream,
    remote_stream: VeilidStream,
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

fn new_connect_proto(call_id: u64, route: &[u8]) -> Vec<u8> {
    let mut conn_builder = Builder::new_default();
    let mut conn = conn_builder.init_root::<proto::call::Builder>();
    conn.set_id(call_id);
    conn.set_route(route);
    return serialize::write_message_to_words(&conn_builder);
}

fn privacy() -> SafetySelection {
    SafetySelection::Safe(SafetySpec {
        sequencing: Sequencing::EnsureOrdered,
        stability: veilid_core::Stability::LowLatency,
        preferred_route: None,
        hop_count: 1,
    })
}
