use std::{io, task::Poll};

use capnp::{message::Builder, serialize};
use flume::Receiver;
use futures_lite::future::FutureExt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
};
use veilid_core::{RoutingContext, Target, VeilidAPIError};

use crate::proto;

/// A network stream built over Veilid app_call primitives.
pub struct AppCallStream {
    /// Unique identifier for the stream. Somewhat analogous to a
    /// dynamically-assigned port number.
    stream_id: u64,

    /// veilid-core routing context, used to write to a remote vldpipe node with
    /// app_call.
    routing_context: RoutingContext,
    
    /// Remote vldpipe node target "address".
    target: Target,

    /// Receiver fed vldpipe payloads via veilid-core node's update-callback,
    /// routed by vldpipe to this stream by stream_id.
    from_veilid: Receiver<Vec<u8>>,

    /// An outbound app_call write task in progress, if any.
    write_handle: Option<JoinHandle<io::Result<usize>>>,

    /// An inbound from_veilid read task in progress, if any.
    read_handle: Option<JoinHandle<io::Result<Vec<u8>>>>,
}

impl AppCallStream {
    pub fn new(
        stream_id: u64,
        routing_context: RoutingContext,
        target: Target,
        from_veilid: Receiver<Vec<u8>>,
    ) -> AppCallStream {
        AppCallStream {
            stream_id,
            routing_context,
            target,
            from_veilid,
            write_handle: None,
            read_handle: None,
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

impl AsyncWrite for AppCallStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let self_mut = self.get_mut();
        let stream_id = self_mut.stream_id;
        let prev_handle = self_mut.write_handle.take();
        let (next_handle, result) = match prev_handle {
            Some(mut h) => {
                // An existing app_call in progress, check on it
                eprintln!("{} poll_write Some(app_call handle) running", stream_id);
                if h.is_finished() {
                    eprintln!("{} poll_write handle has finished!", stream_id);
                    (
                        None,
                        match h.poll(cx) {
                            Poll::Ready(Ok(result)) => Poll::Ready(result),
                            Poll::Ready(Err(e)) => {
                                if e.is_cancelled() {
                                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, e)))
                                } else {
                                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                                }
                            }
                            Poll::Pending => Poll::Pending,
                        },
                    )
                } else {
                    (Some(h), Poll::Pending)
                }
            }
            None => {
                // No prior write in progress, start one app_call
                eprintln!("{} None, start new app_call", stream_id);
                let n = buf.len();
                let (rc, target) = (self_mut.routing_context.clone(), self_mut.target.clone());
                let msg = new_payload_proto(self_mut.stream_id, buf);
                let waker = cx.waker().clone();

                let app_call_task = async move {
                    let result = match rc.app_call(target.clone(), msg).await {
                        Ok(_) => Ok(n),
                        Err(VeilidAPIError::Timeout) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            VeilidAPIError::Timeout,
                        )),
                        Err(VeilidAPIError::InvalidTarget) => Err(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            VeilidAPIError::Timeout,
                        )),
                        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
                    };
                    eprintln!("{} app_call task complete: {:?}", stream_id, result);
                    waker.wake();
                    result
                };
                let handle = tokio::spawn(app_call_task);
                eprintln!("{} app_call task started", stream_id);
                (Some(handle), Poll::Pending)
            }
        };
        self_mut.write_handle = next_handle;
        eprintln!("{} poll_write -> {:?}", stream_id, result);
        result
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        eprintln!("{} shutdown", self.stream_id);
        if let Some(handle) = self.write_handle.as_ref() {
            eprintln!("{} aborting task", self.stream_id);
            handle.abort();
        }
        cx.waker().wake_by_ref();
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for AppCallStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let self_mut = self.get_mut();
        let stream_id = self_mut.stream_id();
        let prev_handle = self_mut.read_handle.take();
        let waker = cx.waker().clone();

        let (next_handle, result) = match prev_handle {
            // An existing read is in progress
            Some(mut handle) => {
                let result = match handle.poll(cx) {
                    Poll::Pending => (Some(handle), Poll::Pending),
                    Poll::Ready(Err(e)) => (
                        None,
                        if e.is_cancelled() {
                            Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, e)))
                        } else {
                            Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                        },
                    ),
                    Poll::Ready(Ok(Err(e))) => (None, Poll::Ready(Err(e))),
                    Poll::Ready(Ok(Ok(bytes_read))) => {
                        buf.put_slice(bytes_read.as_ref());
                        (None, Poll::Ready(Ok(())))
                    }
                };
                eprintln!("{} poll_read task done: {:?}", stream_id, result);
                result
            }
            // No prior read in progress, start one
            None => {
                let from_veilid = self_mut.from_veilid.clone();
                let read_handle = tokio::spawn(async move {
                    let result = match from_veilid.recv_async().await {
                        Ok(b) => Ok(b),
                        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
                    };
                    eprintln!("{} poll_read got result: {:?}", stream_id, result);
                    waker.wake();
                    result
                });
                (Some(read_handle), Poll::Pending)
            }
        };
        self_mut.read_handle = next_handle;
        eprintln!("{} poll_read -> {:?}", stream_id, result);
        result
    }
}

pub fn new_payload_proto(call_id: u64, contents: &[u8]) -> Vec<u8> {
    let mut msg_builder = Builder::new_default();
    let mut msg = msg_builder.init_root::<proto::call::Builder>();
    msg.set_id(call_id);
    msg.set_payload(contents);
    return serialize::write_message_to_words(&msg_builder);
}
