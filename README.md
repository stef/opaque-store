# OPAQUE-Store

OPAQUE-Store is a simple protocol that allows anyone to store
encrypted blobs of information online, with only a password needed to
retrieve the information. As the name implies it uses the OPAQUE
protocol to do so. OPAQUE-Store uses the `export_key` feature of
OPAQUE to encrypt the data that is stored on the OPAQUE-Storage
server.

You might want to read this blog-post on this topic and on more info:
`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

OPAQUE-Store goes beyond the original OPAQUE protocol as specified by
the IRTF/CFRG and also supports a threshold variant of OPAQUE. In a
threshold setup you have a number N of servers that all hold a share
of your secret and at least a threshold number T of these need to
cooperate to recover the secret. This provides extra robustness and
dillution of responsibility (losing a server is not the end of the
world!) while at the same time increases security, as an attacker now
has to compromise at least T servers to get access to some
information.

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
