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
