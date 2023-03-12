#!/usr/bin/env python
#from dissononce.processing.handshakepatterns.deferred.XK1 import XK1HandshakePattern
from dissononce.dh.x25519.x25519 import X25519DH
import sys
import binascii

# setup initiator and responder variables
keypair = X25519DH().generate_keypair()

print("private key", binascii.b2a_base64(keypair.private.data+keypair.public.data).strip().decode("utf8"))
print("public key", binascii.b2a_base64(keypair.public.data).strip().decode("utf8"))
