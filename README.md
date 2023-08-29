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

Should eventually pair nicely with podman-compose and the like.

# Demo

Serving up the project source on port 8000, exporting it to Veilid, importing from Veilid _back_ to the same machine on port 9000. Useless but fun.

[![asciicast](https://asciinema.org/a/Dmh396J39LRuKqRYV7MQXKb9u.svg)](https://asciinema.org/a/Dmh396J39LRuKqRYV7MQXKb9u)

# TODO

Persistent node identities & DHT addresses.

Patched veilid-core to start nodes faster? Or upstream fix for this... configuration option? There's about a 1m5s delay for the node to go online.

Renegotiating private routes. I've observed persistent InvalidTarget failures, which seems to indicate that routes can churn and need to be rebuilt automatically.

Authenticated encryption like Tor stealth HS.

No idea how secure this really is yet.

# Credits

Examples in veilid-core and https://gitlab.com/bbigras/netdog were super-helpful in figuring out how to set things up.

