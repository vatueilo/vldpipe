use std::collections::HashMap;

use capnp::{message::{ReaderOptions, Builder}, serialize};
use flume::{unbounded, Receiver, Sender};
use tokio::task::JoinHandle;
use veilid_core::{
    DHTRecordDescriptor, RoutingContext, Target, VeilidAPIError, VeilidAPIResult, VeilidUpdate,
};

use crate::{
    proto::{self},
    stream::{AppCallStream, new_payload_proto},
};

pub struct AppCallListener {
    client_stream_receiver: Receiver<AppCallStream>,
    handler: JoinHandle<VeilidAPIResult<()>>,
}

impl AppCallListener {
    pub async fn bind(
        routing_context: RoutingContext,
        from_node: Receiver<VeilidUpdate>,
        addr: DHTRecordDescriptor,
    ) -> VeilidAPIResult<AppCallListener> {
        let (_inbound_key, inbound_blob) = routing_context.api().new_private_route().await?;
        routing_context
            .set_dht_value(addr.key().to_owned(), 0, inbound_blob.clone())
            .await?;

        let (client_stream_sender, client_stream_receiver): (
            Sender<AppCallStream>,
            Receiver<AppCallStream>,
        ) = unbounded();
        Ok(AppCallListener {
            client_stream_receiver,
            handler: tokio::spawn(async move {
                Self::handle_node_updates(
                    routing_context,
                    from_node,
                    client_stream_sender,
                    inbound_blob,
                )
                .await
            }),
        })
    }

    pub async fn accept(&self) -> VeilidAPIResult<AppCallStream> {
        let client_stream = self
            .client_stream_receiver
            .recv_async()
            .await
            .map_err(|e| VeilidAPIError::Generic {
                message: e.to_string(),
            })?;
        eprintln!("accept: got stream_id={}", client_stream.stream_id());
        Ok(client_stream)
    }

    pub async fn close(self) -> VeilidAPIResult<()> {
        self.handler.abort();
        self.handler.await.map_err(|e| VeilidAPIError::Generic {
            message: e.to_string(),
        })?
    }

    async fn handle_node_updates(
        routing_context: RoutingContext,
        from_node: Receiver<VeilidUpdate>,
        client_stream_sender: Sender<AppCallStream>,
        inbound_blob: Vec<u8>,
    ) -> VeilidAPIResult<()> {
        let mut stream_senders = HashMap::new();
        loop {
            // Receive and decode app_call from veilid-core updates
            let (stream_id, call_id, maybe_connect, maybe_payload) = match from_node
                .recv_async()
                .await
                .map_err(|e| veilid_core::VeilidAPIError::Generic {
                    message: e.to_string(),
                }) {
                Ok(VeilidUpdate::AppCall(app_call)) => {
                    let app_call_id = app_call.id();
                    eprintln!("got app_call {}", app_call_id);
                    let reader =
                        serialize::read_message(app_call.message(), ReaderOptions::new()).unwrap();
                    let call_msg = reader.get_root::<proto::call::Reader>().unwrap();
                    eprintln!("export: got app_call {:?}", call_msg);
                    match call_msg.which() {
                        Ok(proto::call::Which::Connect(Ok(connect))) => {
                            (app_call_id.into(), app_call_id, Some(connect.to_owned()), None)
                        }
                        Ok(proto::call::Which::Payload(Ok(payload))) => {
                            (call_msg.get_id(), app_call_id, None, Some(payload.to_owned()))
                        }
                        _ => (app_call_id.into(), app_call_id, None, None),
                    }
                }
                Ok(VeilidUpdate::Shutdown) => return Ok(()),
                Ok(_) => continue,
                Err(e) => return Err(e),
            };

            // Dispatch valid app_call
            match (maybe_connect, maybe_payload) {
                (Some(connect), _) => {
                    // A new connection request. Create an AppCallStream for it
                    // and send it to be accept()-ed.
                    let conn_outbound_target = Target::PrivateRoute(
                        routing_context
                            .api()
                            .import_remote_private_route(connect.to_vec())?,
                    );
                    eprintln!(
                        "export: {} imported connection outbound target {:?}",
                        stream_id, conn_outbound_target
                    );

                    // TODO: create separate private route for each connection?
                    // Maybe this should be an option?
                    // What are the security tradeoffs?
                    //
                    //let (conn_inbound_key, conn_inbound_blob) = new_private_route(&api).await?;
                    //eprintln!("export: {} created connection inbound route {:?}", call_id, conn_inbound_key);

                    // Create a sender / receiver for the forward
                    let (stream_sender, stream_receiver): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
                        unbounded();
                    stream_senders.insert(stream_id, stream_sender);

                    let remote_stream = AppCallStream::new(
                        stream_id,
                        routing_context.clone(),
                        conn_outbound_target,
                        stream_receiver,
                    );
                    client_stream_sender.send(remote_stream).map_err(|e| {
                        VeilidAPIError::Generic {
                            message: e.to_string(),
                        }
                    })?;

                    let connect_reply = new_connect_proto(stream_id, &inbound_blob);
                    match routing_context
                        .api()
                        .app_call_reply(call_id, connect_reply)
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("export: app_call_reply for {} failed: {:?}", call_id, e);
                            eprintln!("export: removing sender for: {}", stream_id);
                            stream_senders.remove(&stream_id);
                        }
                    }
                }
                (None, Some(payload)) => {
                    // Route and send payload to the right stream
                    match stream_senders.get(&stream_id) {
                        Some(stream_sender) => {
                            if let Err(_) = stream_sender.send(payload.to_vec()) {
                                eprintln!("stream_id={} is gone, removing sender", stream_id);
                                stream_senders.remove(&stream_id);
                            }
                            eprintln!("sent payload to stream_id={}", stream_id);
                        }
                        None => {
                            eprintln!("no matching stream_id={}", stream_id);
                        }
                    }

                    match routing_context
                        .api()
                        .app_call_reply(call_id, new_payload_proto(stream_id, &[]))
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("app_call_reply for stream_id={} failed: {:?}", stream_id, e);
                            eprintln!("removing stream_id={}", stream_id);
                            stream_senders.remove(&stream_id);
                        }
                    };
                }
                _ => {}
            };
        }
    }
}

fn new_connect_proto(call_id: u64, route: &[u8]) -> Vec<u8> {
    let mut conn_builder = Builder::new_default();
    let mut conn = conn_builder.init_root::<proto::call::Builder>();
    conn.set_id(call_id);
    conn.set_connect(route);
    return serialize::write_message_to_words(&conn_builder);
}
