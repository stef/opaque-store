# OPAQUE-Store server

OPAQUE-Store is a simple protocol that allows anyone to store
encrypted blobs of information online, with only a password needed to
retrieve the information. As the name implies it uses the OPAQUE
protocol to do so. OPAQUE-Store uses the `export_key` feature of
OPAQUE to encrypt the data that is stored on the OPAQUE-Storage
server.

# Dependencies

you need to install

 - libsodium
 - liboprf https://github.com/stef/liboprf/
 - libopaque https://github.com/stef/libopaque/

on debian (unstable) you can install the -dev packages.

# Building

You need zig 0.13 at least to build, simply do

  `zig build`

# Configuring

Configuration will be looked for in the following order

  - /etc/opaque-stored/config
  - ~/.config/opaque-stored/config
  - ~/.opaque-storedrc
  - ./opaque-stored.cfg

For an example file see the file `opaque-stored.cfg` in this directory.

The most important is to have a proper SSL certificate, in the times of Let's
Encrypt this should not be a big challenge. You do need a domain name you
control for this though, but that is a requirement for public servers
anyway. If you have a domain name, you can run on that host something like
this:

```sh
sudo certbot certonly --standalone --preferred-challenges http -d example.com
```

If you run a server that is publicly available on the internet, we recommend to
run it on port 443, which - if you ever go to a restricted network environmet -
has the biggest chances that a firewall will allow to access this.

## Configuration Example

The following is a basic configuration example for a server.

```
[server]
# the ipv4 address the server is listening on
#address="127.0.0.1"

# ssl key
ssl_key="server.der"

# ssl cert
ssl_cert="cert.pem"

# the port on which the server is listening, use 443 if available, so that
# the server can be accessed from behind tight firewalls, default: 8080
port=2523

# tcp connection timeouts, increase in case you have bad networks, with the
# caveat that this might lead to easier resource exhaustion - blocking all
# workers.
#timeout=3

# the root directory where all data is stored, default: /var/lib/opaque-stored
datadir="data"

# how many worker processes can run in parallel
# max_kids=5

# whether to produce some output
verbose=true

# key
record_salt="some random string to salt the record ids"

# Especially if you run a public server you want to limit the maximum size of
# stored blobs
max_blob_size=8192

# lock a record after this many failed password attempts.
max_fails=3

# a file containing the long-term signing key of the server - this is only
# needed for participation in threshold setups. Can be generated by running the
# client with parameter: "opaquestore genltsigkey >ltsigkey.key"
ltsigkey="ltsigkey.key"

# set how long a message is considered fresh during a DKG protocol, any
# messages that have timestamps that are older than this many seconds will
# abort the DKG protocol. Increase this value if you have/expect laggy links.
ts_epsilon=600

# the number of recovery tokens a server holds for each blob
max_recovery_tokens=5
```
