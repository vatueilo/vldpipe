# vldpipe

A most valid pipe.

Publish and consume TCP services over the [Veilid](https://veilid.com) network.

Not working yet.

# Put this in your valid pipe and smoke it

Publishing host exports a local socket address to Veilid. This form is `vldpipe [local address]`.

```
vldpipe 8080
# Copy "that DHT key"
```

Consuming hosts can import this service and bind it to local addresses with:

```
vldpipe [that DHT key] 127.0.0.1:9000
```

Or serve it on all interfaces (local lan, public wan ingress) with:

```
vldpipe [that DHT key] 0.0.0.0:9000
```

Should pair nicely with podman-compose and the like.

# TODO

Persistent node identities & DHT addresses.

Attributions to veilid-core and https://gitlab.com/bbigras/netdog.

Message handler is totally wrong. Need to redo it, implement proper dispatching and stream tracking. Was lazily avoiding that but that was a mistake.

Authenticated encryption like Tor stealth HS.

No idea how secure this is yet.

