#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

from klutshnik.wrapper import thresholdmult, DKG, Evaluate, KEYID_SIZE, VERSION as KLUTSHNIK_VERSION
from klutshnik.utils import split_by_n
from klutshnik.noiseclient import connect, gather
import ctypes as c

config = None

lib = c.cdll.LoadLibrary(c.util.find_library('oprf') or
                         c.util.find_library('liboprf.so') or
                         c.util.find_library('liboprf') or
                         c.util.find_library('liboprf0'))
if not lib._name:
   raise ValueError('Unable to find liboprf')

@c.CFUNCTYPE(c.c_int, c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte), c.POINTER(c.c_ubyte))
def eval(keyid, alpha, beta):
  servers=config['servers']
  n = len(servers)
  t = config['threshold']
  keyid_ = bytes(keyid[:16])
  conns = connect(servers, Evaluate, t, n, keyid_, config['key'], config['authkey'], KLUTSHNIK_VERSION)

  msg = bytes(alpha[:32]) + bytes(alpha[:32])
  for index,conn in enumerate(conns):
    # todo eval needs also a verifier, which we ignore here...
    conn.sendall(msg)

  # receive responses from tuokms_evaluate
  responders=gather(conns, 33*2, n, lambda pkt: (pkt[:33], pkt[33:]))

  xresps = tuple(responders[i][0] for i in range(n))

  # we only select the first t shares, should be rather random
  beta_ = thresholdmult(t, xresps)

  c.memmove(beta, beta_, len(beta_))

  return 0

@c.CFUNCTYPE(None, c.POINTER(c.c_ubyte))
def keygen(keyid):
  # slightly simpler than klutshnik dkg
  n = len(config['servers'])
  threshold = config['threshold']
  keyid_ = pysodium.randombytes(KEYID_SIZE)
  conns = connect(config['servers'], DKG, threshold, n, keyid_, config['key'], config['authkey'], KLUTSHNIK_VERSION)

  responders=gather(conns, (pysodium.crypto_core_ristretto255_BYTES * threshold) + (33*n*2), n, lambda x: (x[:threshold*pysodium.crypto_core_ristretto255_BYTES], split_by_n(x[threshold*pysodium.crypto_core_ristretto255_BYTES:], 2*33)) )

  commitments = b''.join(responders[i][0] for i in range(n))
  for i in range(n):
      shares = b''.join([responders[j][1][i] for j in range(n)])
      msg = commitments + shares
      conns[i].sendall(msg)

  oks = gather(conns, 66, n)

  authtoken = conns[0].read_pkt(0)
  #setauthkey(keyid_,authtoken)
  print("authtoken for new key: ", b2a_base64(authtoken).decode('utf8').strip())
  for conn in conns:
    conn.fd.close()

  c.memmove(keyid, keyid_, len(keyid_))
