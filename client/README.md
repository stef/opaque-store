# OPAQUE-Store

This is a simple client-server system, which implements a simple online storage
of blobs, which can be recovered using only a password.

You might want to read this blogpost on this topic and on more info:
`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

** Installation

opaquestore depends on https://github.com/stef/libopaque/ which in turn
depends on libsodium and liboprf, and pyoprf.

When you have libopaque, a simple `pip install opaquestore` should get you started.

# TODO all of the below are out-dated and need update

## API

The client provides two simple functions for creating and querying blobs:

Store a new blob:

```python
  from opaquestore import opaquestore
  from opaquestore.noiseclient import NoiseWrapper
  s = NoiseWrapper.connect(cfg['address'], cfg['port'], cfg['noise_key'], cfg['server_pubkey'])
  opaquestore.create(s, password, blob_id, blob)
```

To query an existing blob:

```python
  from opaquestore import opaquestore
  from opaquestore.noiseclient import NoiseWrapper
  s = NoiseWrapper.connect(cfg['address'], cfg['port'], cfg['noise_key'], cfg['server_pubkey'])
  blob = opaquestore.get(s, password, blob_id)
```

The `cfg` variable should be loaded with the values from a configfile or otherwise populated.

## Configfiles

For an example and documentation on the values in the config files
see: opaque-store.cfg for the client config, and opaque-stored.cfg for
the server config.

## Example

Generate keys

```
opaquestore genkey
```

This should output a private key and a public key, these you can/should use in the configfiles.

Run the server

```
opaquestore server
```

Store a new blob:

```
echo -en "mypassword\!sMyV0ice\nmy secretty token data that i need to protect and store using opaque" | opaquestore create cfba1e747f706b542451a9d5404346f8
```

the password and the blob are expected on stdin, in this order,
seperated by a newline. The second parameter to the client is an ID
used to refer to the blob.

Recall the blob:

```
echo -en "mypassword\!sMyV0ice" | opaquestore get cfba1e747f706b542451a9d5404346f8
```

The password is again supplied on stdin, and the same ID as used for
creation is used as reference.
