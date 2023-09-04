use std::collections::HashMap;

use capnp::message::ReaderOptions;
use capnp::serialize;
use flume::{unbounded, Receiver, Sender};
use tokio::select;
use tokio::task::JoinHandle;
use veilid_core::{
    DHTRecordDescriptor, RoutingContext, Target, VeilidAPIError, VeilidAPIResult, VeilidUpdate,
};

use crate::listener::new_connect_proto;
use crate::stream::AppCallStream;
use crate::{proto, stream};

pub struct Dialer {
    routing_context: RoutingContext,
    inbound_blob: Vec<u8>,
    payload_sender_sender: Sender<(u64, Sender<Vec<u8>>)>,
    handler: JoinHandle<VeilidAPIResult<()>>,
}

impl Dialer {
    pub async fn new(
        routing_context: RoutingContext,
        from_node: Receiver<VeilidUpdate>,
    ) -> VeilidAPIResult<Dialer> {
        let (_inbound_addr, inbound_blob) = routing_context.api().new_private_route().await?;
        let (payload_sender_sender, payload_sender_receiver) = unbounded();
        Ok(Dialer {
            routing_context: routing_context.clone(),
            inbound_blob,
            payload_sender_sender,
            handler: tokio::spawn(async move {
                Self::handle_node_updates(routing_context, from_node, payload_sender_receiver).await
            }),
        })
    }

    async fn handle_node_updates(
        routing_context: RoutingContext,
        from_node: Receiver<VeilidUpdate>,
        payload_sender_receiver: Receiver<(u64, Sender<Vec<u8>>)>,
    ) -> VeilidAPIResult<()> {
        let mut stream_senders: HashMap<u64, Sender<Vec<u8>>> = HashMap::new();
        loop {
            select! {
                node_res = from_node.recv_async() => {
                    let (stream_id, call_id, payload) = match node_res {
                        Ok(VeilidUpdate::AppCall(app_call)) => {
                            eprintln!("dialer: got app_call {:?}", app_call);
                            match read_call_message(app_call.message())? {
                                Some((id, payload)) => (id, app_call.id(), payload),
                                None => {
                                    eprintln!("dialer: invalid call");
                                    continue
                                }
                            }
                        }
                        Ok(VeilidUpdate::Shutdown) => {
                            eprintln!("dialer: shutdown received");
                            return Ok(());
                        }
                        Ok(_) => {
                            continue;
                        }
                        Err(e) => {
                            eprintln!("recv failed, {}", e);
                            continue;
                        }
                    };

                    // route message to the right forward
                    match stream_senders.get(&stream_id) {
                        Some(sender) => {
                            if let Err(_) =
                                sender.send(payload.to_vec())
                            {
                                eprintln!("dialer: forward is gone, removing sender");
                                stream_senders.remove(&stream_id);
                                continue
                            } else {
                                eprintln!("dialer: sent payload to forwarding stream {}", stream_id);
                            }
                        }
                        None => {
                            eprintln!("dialer: no such stream_id={}", stream_id);
                        }
                    }

                    match routing_context.api().app_call_reply(call_id, stream::new_payload_proto(stream_id, &[])).await {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("dialer: app_call_reply for {} failed: {:?}",stream_id, e);
                            eprintln!("dialer: removing sender for: {}", stream_id);
                            stream_senders.remove(&stream_id);
                            continue
                        }
                    };
                    eprintln!("dialer: handled app_call for {}", stream_id);
                }
                ps_res = payload_sender_receiver.recv_async() => {
                    match ps_res {
                        Ok((stream_id, stream_sender)) => {
                            eprintln!("dialer: registered sender for stream_id={}", stream_id);
                            stream_senders.insert(stream_id, stream_sender);
                        }
                        Err(e) => return Err(VeilidAPIError::Generic { message: e.to_string() })
                    }
                }
            }
        }
    }

    pub async fn dial(&self, addr: DHTRecordDescriptor) -> VeilidAPIResult<AppCallStream> {
        let connect_target = self.resolve(addr).await?;
        eprintln!("dialer: resolved {:?}", connect_target);

        let (stream_id, outbound_target) = self.connect(connect_target).await?;
        eprintln!("dialer: connected stream_id={}", stream_id);

        let (payload_sender, payload_receiver) = unbounded();
        self.payload_sender_sender
            .send((stream_id, payload_sender))
            .map_err(generic_err)?;
        Ok(AppCallStream::new(
            stream_id,
            self.routing_context.clone(),
            outbound_target,
            payload_receiver,
        ))
    }

    async fn resolve(&self, addr: DHTRecordDescriptor) -> VeilidAPIResult<Target> {
        let remote_entry = self
            .routing_context
            .get_dht_value(addr.key().to_owned(), 0, true)
            .await?;
        let remote_blob = match remote_entry {
            Some(entry) => entry.data().to_vec(),
            None => {
                return Err(generic_err("address has not published a route"));
            }
        };
        Ok(Target::PrivateRoute(
            self.routing_context
                .api()
                .import_remote_private_route(remote_blob)?,
        ))
    }

    async fn connect(&self, target: Target) -> VeilidAPIResult<(u64, Target)> {
        let connect_msg = new_connect_proto(0, &self.inbound_blob);
        let resp = self.routing_context.app_call(target, connect_msg).await?;
        let reader =
            serialize::read_message(resp.as_slice(), ReaderOptions::new()).map_err(generic_err)?;
        let call = reader
            .get_root::<proto::call::Reader>()
            .map_err(generic_err)?;

        let call_id: u64 = call.get_id().into();
        let outbound_blob = match call.which() {
            Ok(proto::call::Which::Connect(Ok(route))) => route.to_owned(),
            Ok(_) => {
                return Err(generic_err("invalid connect response"));
            }
            Err(e) => {
                return Err(generic_err(e));
            }
        };
        let outbound_key = self
            .routing_context
            .api()
            .import_remote_private_route(outbound_blob)?;
        Ok((call_id, Target::PrivateRoute(outbound_key)))
    }

    pub async fn close(self) -> VeilidAPIResult<()> {
        self.handler.abort();
        self.handler.await.map_err(|e| VeilidAPIError::Generic {
            message: e.to_string(),
        })?
    }
}

fn generic_err<T: ToString>(e: T) -> VeilidAPIError {
    VeilidAPIError::Generic {
        message: e.to_string(),
    }
}

fn read_call_message(msg: &[u8]) -> VeilidAPIResult<Option<(u64, Vec<u8>)>> {
    let reader = serialize::read_message(msg, ReaderOptions::new()).map_err(generic_err)?;
    let call = reader
        .get_root::<proto::call::Reader>()
        .map_err(generic_err)?;
    Ok(match call.which() {
        Ok(proto::call::Which::Payload(Ok(p))) => Some((call.get_id(), p.to_vec())),
        Ok(_) => {
            eprintln!("dialer: invalid call: {:?}", call);
            None
        }
        Err(e) => {
            eprintln!("dialer: invalid call: {:?}", e);
            None
        }
    })
}
