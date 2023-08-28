mod config;
mod proto;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{env, io, net, result};

use backoff::ExponentialBackoff;
use capnp::message::{Builder, ReaderOptions};
use capnp::serialize;
use clap::Parser;
use thiserror::Error;

use flume::{unbounded, Receiver, Sender};

use tokio::net::{TcpListener, TcpSocket};
use tokio::select;
use veilid_core::{
    AttachmentState, CryptoKey, OperationId, RoutingContext, Sequencing, VeilidAPIResult,
};
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
    let (node_sender, node_receiver): (
        Sender<veilid_core::VeilidUpdate>,
        Receiver<veilid_core::VeilidUpdate>,
    ) = unbounded();

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
        select! {
            res = node_receiver.recv_async() => {
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
            let mut fwd_map = HashMap::new();

            // Veilid "bind()"
            // Create an in-bound route to handle new connections, like a port
            let (_inbound_key, ln_inbound_blob) = new_private_route(&api).await?;
            // Store its routing blob in DHT
            // TODO: is this secure?
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
            // Print the DHT key, this is what clients can "connect()" to
            eprintln!("listening on {}", ln_inbound_dht.key());

            loop {
                match node_receiver.recv_async().await {
                    Ok(VeilidUpdate::AppCall(call)) => {
                        // "accept()" with privacy, build a "socket pair"
                        //
                        // write-side (outbound): import the remote's private route to send responses to
                        // read-side (inbound): create a private route and reply with it, and the "socket" id
                        //
                        // For now we'll abuse the RPC call_id for this id out
                        // of laziness but this might not be secure, think about
                        // TCP sequence numbers :)
                        eprintln!("accept: {:?}", call);
                        let call_id: u64 = call.id().into();
                        let conn_outbound_target = Target::PrivateRoute(
                            api.import_remote_private_route(call.message().to_vec())?,
                        );
                        eprintln!(
                            "imported connection outbound target {:?}",
                            conn_outbound_target
                        );

                        // creating inbound private route for connection responses
                        //let (conn_inbound_key, conn_inbound_blob) = new_private_route(&api).await?;
                        //eprintln!("created connection inbound route {:?}", conn_inbound_key);

                        eprintln!("starting forward");
                        let socket = TcpSocket::new_v4()?;

                        // Create a sender / receiver for the forward
                        let (fwd_sender, fwd_receiver): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
                            unbounded();
                        fwd_map.insert(call_id, fwd_sender);

                        tokio::spawn(export_forward(
                            call_id,
                            conn_outbound_target.clone(),
                            socket.connect(from_local).await?,
                            routing_context.clone(),
                            fwd_receiver.clone(),
                        ));
                        eprintln!("started forward");

                        // TODO: possible data race here if the forward doesn't start selecting in time for the
                        // remote to start sending messages.

                        let connect_reply = new_connect_proto(call_id, &[]);
                        match api.app_call_reply(call.id(), connect_reply).await {
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("app_call_reply failed: {:?}", e);
                                eprintln!("removing sender for: {}", call_id);
                                fwd_map.remove(&call_id);
                            }
                        }
                        eprintln!("replied to caller");
                    }
                    Ok(VeilidUpdate::Shutdown) => {
                        break;
                    }
                    Ok(VeilidUpdate::AppMessage(msg)) => {
                        // decode call id out of message
                        // TODO: ignore malformed messages, we'll just panic for now
                        let reader =
                            serialize::read_message(msg.message.as_slice(), ReaderOptions::new())
                                .unwrap();
                        let conn = reader.get_root::<proto::message::Reader>().unwrap();

                        // route message to the right forward
                        let call_id: u64 = conn.get_id().into();
                        match fwd_map.get(&call_id) {
                            Some(fwd_sender) => {
                                if let Err(_) =
                                    fwd_sender.send(conn.get_contents().unwrap().to_vec())
                                {
                                    eprintln!("forward is gone, removing sender");
                                    fwd_map.remove(&call_id);
                                    break;
                                }
                            }
                            None => {}
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("recv failed, {}", e);
                        break;
                    }
                };
            }
            eprintln!("export loop ended");
        }
        PipeSpec::Import {
            from_remote,
            ref to_local,
        } => {
            let mut fwd_map = HashMap::new();

            // get the private route blob from DHT, import it as listener_target
            let remote_target = get_remote_route(api.clone(), from_remote.to_owned()).await?;

            let local_ln = TcpListener::bind(to_local).await?;
            eprintln!("started local listener on {}", to_local);

            loop {
                select! {
                    // Accept local TCP connection
                    accept_res = local_ln.accept() => {
                        match accept_res {
                            Ok((local_stream, local_addr)) => {
                                eprintln!("accepted connection from {}", local_addr);
                                // Connect to remote target
                                let (conn_inbound_addr, conn_inbound_blob) = new_private_route(&api).await?;
                                eprintln!(
                                    "created new inbound connection route {:?}",
                                    conn_inbound_addr
                                );
                                let routing_context = api
                                    .routing_context()
                                    .with_sequencing(Sequencing::EnsureOrdered)
                                    .with_privacy()?;
                                eprintln!("calling remote for outbound target");
                                let call_id: u64;
                                //let conn_outbound_blob: Vec<u8>;

                                // Veilid "connect()"
                                match app_call(&routing_context, remote_target.clone(), conn_inbound_blob.clone()).await {
                                    Ok(resp) => {
                                        let reader =
                                            serialize::read_message(resp.as_slice(), ReaderOptions::new())
                                                .unwrap();
                                        let conn = reader.get_root::<proto::connect::Reader>().unwrap();

                                        call_id = conn.get_id();
                                        //conn_outbound_blob = conn.get_route().unwrap().to_vec();
                                    }
                                    Err(VeilidAPIError::InvalidTarget) => {
                                        eprintln!("invalid target");
                                        continue;
                                    }
                                    Err(e) => {
                                        eprintln!("failed to connect: {:?}", e);
                                        continue;
                                    }
                                }

                                // Create a sender / receiver for the forward
                                let (fwd_sender, fwd_receiver): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
                                fwd_map.insert(call_id, fwd_sender);

                                // make rpc call to listener_target, get remote private route, import as conn_target
                                //let conn_outbound_target =
                                //    Target::PrivateRoute(api.import_remote_private_route(conn_outbound_blob)?);
                                //eprintln!("got outbound connection target {:?}", conn_outbound_target);
                                eprintln!("starting forward");
                                tokio::spawn(export_forward(
                                    call_id,
                                    remote_target.clone(),
                                    local_stream,
                                    routing_context.clone(),
                                    fwd_receiver.clone(),
                                ));
                                eprintln!("forward started");
                            }
                            Err(e) => {
                                return Err(AppError::IO(e))
                            }
                        }
                    }
                    node_res = node_receiver.recv_async() => {
                        match node_res {
                            Ok(VeilidUpdate::AppMessage(msg)) => {
                                // decode call id out of message
                                // TODO: ignore malformed messages, we'll just panic for now
                                let reader = serialize::read_message(
                                    msg.message.as_slice(),
                                    ReaderOptions::new(),
                                )
                                .unwrap();
                                let conn = reader.get_root::<proto::message::Reader>().unwrap();
                                eprintln!("got app_message {:?}", conn);

                                // route message to the right forward
                                let call_id: u64 = conn.get_id().into();
                                match fwd_map.get(&call_id) {
                                    Some(fwd_sender) => {
                                        if let Err(_) =
                                            fwd_sender.send(conn.get_contents().unwrap().to_vec())
                                        {
                                            eprintln!("forward is gone, removing sender");
                                            fwd_map.remove(&call_id);
                                        }
                                    }
                                    None => {}
                                }
                                eprintln!("handled app_message");
                            }
                            Ok(VeilidUpdate::Shutdown) => {
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
        }
    };

    api.detach().await?;
    api.shutdown().await;
    Ok(())
}

async fn get_remote_route(api: VeilidAPI, from_remote: String) -> VeilidAPIResult<Target> {
    backoff::future::retry(ExponentialBackoff::default(), || async {
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
    })
    .await
}

async fn export_forward(
    call_id: u64,
    target: Target,
    mut local_stream: tokio::net::TcpStream,
    routing_context: RoutingContext,
    receiver: Receiver<Vec<u8>>,
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
                                if n == 0 {
                                    continue
                                }
                                eprintln!("read {} bytes from local stream", n);

                                let msg = new_message_proto(call_id, &rd_buf[..n]);
                                match app_message(&routing_context, target.clone(), msg.clone()).await {
                                    Ok(_) => {},
                                    Err(e) => return Err(AppError::API(e)),
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
                    Ok(message) => {
                        eprintln!("writing message from remote {:?}", message);
                        // TODO: error handling, deal with partial writes, blah blah
                        let mut wr = 0;
                        while wr < message.len() {
                            local_write.writable().await?;
                            match local_write.try_write(&message[wr..]) {
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
                            eprintln!("wrote {} of {}", wr, message.len());
                        }
                    }
                    Err(_) => {
                        return Ok(());
                    }
                }
            }
        };
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

async fn app_call(
    routing_context: &RoutingContext,
    target: Target,
    message: Vec<u8>,
) -> VeilidAPIResult<Vec<u8>> {
    backoff::future::retry_notify(
        ExponentialBackoff::default(),
        || async {
            match routing_context
                .app_call(target.clone(), message.clone())
                .await
            {
                Ok(resp) => Ok(resp),
                Err(VeilidAPIError::InvalidTarget) => {
                    Err(backoff::Error::Permanent(VeilidAPIError::InvalidTarget))
                }
                Err(e) => Err(backoff::Error::Transient {
                    err: e,
                    retry_after: None,
                }),
            }
        },
        |e, dur| {
            eprintln!("app_call failed: {:?} after {:?}", e, dur);
        },
    )
    .await
}

async fn app_message(
    routing_context: &RoutingContext,
    target: Target,
    message: Vec<u8>,
) -> VeilidAPIResult<()> {
    backoff::future::retry_notify(
        ExponentialBackoff::default(),
        || async {
            match routing_context
                .app_message(target.clone(), message.clone())
                .await
            {
                Ok(()) => Ok(()),
                Err(VeilidAPIError::InvalidTarget) => {
                    Err(backoff::Error::Permanent(VeilidAPIError::InvalidTarget))
                }
                Err(e) => Err(backoff::Error::Transient {
                    err: e,
                    retry_after: None,
                }),
            }
        },
        |e, dur| {
            eprintln!("app_message failed: {:?} after {:?}", e, dur);
        },
    )
    .await
}

fn new_connect_proto(call_id: u64, route: &[u8]) -> Vec<u8> {
    let mut conn_builder = Builder::new_default();
    let mut conn = conn_builder.init_root::<proto::connect::Builder>();
    conn.set_id(call_id);
    conn.set_route(route);
    return serialize::write_message_to_words(&conn_builder);
}

fn new_message_proto(call_id: u64, contents: &[u8]) -> Vec<u8> {
    let mut msg_builder = Builder::new_default();
    let mut msg = msg_builder.init_root::<proto::message::Builder>();
    msg.set_id(call_id);
    msg.set_contents(contents);
    return serialize::write_message_to_words(&msg_builder);
}
