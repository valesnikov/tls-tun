# TLS tunnel

Simple L3 TLS tunnel that can handle one client at a time.

Client is authenticated using TLS.

Client routes all IPv4 traffic to the tunnel, except the packets with fwmark `2720184` (can be changed by setting `--fwmark` flag).

Each time session init ack is exchanged, the previous client's socket is closed by the server.

Certainly not a production ready project.

## Certs

```bash
openssl req -x509 -nodes -newkey rsa:4096 -addext "subjectAltName = IP:12.34.56.78" -keyout server.key -out server.cert -sha256
openssl req -x509 -nodes -newkey rsa:4096 -keyout client.key -out client.cert -sha256
```

## Run

Client:

```bash
./tls-tun -c $SERVER_HOST \
          -s \
          --server-cert server.cert \
          --client-key client.key \
          --client-cert client.cert \
          tls-tun0 10.0.0.2/24
```

Server:

```bash
./tls-tun -l $BIND_ADDR \
          -s \
          --server-cert server.cert \
          --server-key server.key \
          --client-cert client.cert \
          tls-tun0 10.0.0.1/24
```
