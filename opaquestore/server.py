#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import socket, sys, os, datetime, os.path, traceback
import pysodium, opaque
from dissononce.dh.x25519.keypair import KeyPair
from dissononce.dh.x25519.public import PublicKey
from binascii import a2b_base64, b2a_base64
from klutshnik.utils import getcfg
from opaquestore import toprf
from opaquestore.noiseclient import NoiseWrapperServer

config = None

CREATE   =b'\x00'
GET      =b'\x66'
EXOP     =b'\xE0' # unimplemented

normal = "\033[38;5;%sm"
reset = "\033[0m"

def processcfg(config):
  config['noise_key']=KeyPair.from_bytes(a2b_base64(config['noise_key']+'=='))
  config['id_nonce']=a2b_base64(config['id_nonce']+'==')

  if 'servers' in config:
    print("found servers in config, switching to threshold opaque")
    toprf.lib.oprf_set_evalproxy(toprf.eval, toprf.keygen)
    config['servers'] = [(v.get('host',"localhost"),
                          v.get('port'),
                          PublicKey(a2b_base64(v['pubkey'])))
                         for k,v in config.get('servers',{}).items()]
    if not 'authkey' in config:
      raise ValueError("authkey for threshold setup missing config")
    config['authkey']=a2b_base64(config['authkey']+'==')

  with open(config['key'],'rb') as fd:
    config['key']=KeyPair.from_bytes(a2b_base64(fd.read()))

  return config

def fail(s):
  if config['verbose']:
    traceback.print_stack()
    print('fail')
  s.send(b'\x00\x04fail') # plaintext :/
  s.shutdown(socket.SHUT_RDWR)
  s.close()
  os._exit(0)

def pop(obj, cnt):
  return obj[:cnt], obj[cnt:]

def load(keyid):
  rec_id = pysodium.crypto_generichash(keyid,config['id_nonce']).hex()
  rec_path = os.path.join(config['ots_path'], rec_id)
  rec, blob = None, None
  with open(os.path.join(rec_path,"rec"),'rb') as fd:
      rec = fd.read()
  with open(os.path.join(rec_path,"blob"),'rb') as fd:
      blob = fd.read()
  return rec, blob

def create(s, data):
  sec, pub = opaque.CreateRegistrationResponse(data)
  s.sendall(pub)

  keyid = s.read_pkt(0)
  rec0 = s.read_pkt(0)
  blob  = s.read_pkt(0)

  rec = opaque.StoreUserRecord(sec, rec0)

  rec_id = pysodium.crypto_generichash(keyid,config['id_nonce']).hex()
  rec_path = os.path.join(config['ots_path'], rec_id)
  if not os.path.exists(rec_path):
    os.makedirs(rec_path, 0o700, exist_ok=True)
  with open(os.path.join(rec_path,"rec"),'wb') as fd:
      fd.write(rec)
  with open(os.path.join(rec_path,"blob"),'wb') as fd:
      fd.write(blob)

  s.sendall(b'ok')

def get(s, keyid):
  rec, blob = load(keyid)
  pub = s.read_pkt(0)
  ## server responds to credential request
  ids=opaque.Ids(keyid, f"{config['address']}:{config['port']}")
  resp, _, _ = opaque.CreateCredentialResponse(pub, rec, ids, config.get('context',"opaque-store"))

  s.sendall(resp)
  s.sendall(blob)

def exop(s, keyid):
  # unimplemented
  # deoes a full OPAQUE and setups a protected channel to communicate any changes to the record
  rec, blob = load(keyid)
  pub = s.read_pkt(0)
  ## server responds to credential request
  ids=opaque.Ids(keyid, f"{config['address']}:{config['port']}")
  resp, sk, authU0 = opaque.CreateCredentialResponse(pub, rec, ids, config.get('context',"opaque-store"))

  s.sendall(resp)
  s.sendall(blob)

  # todo handle UPDATE, DELETE, CHANGE_PASSWD

def handler(conn):
  pkt = conn.read_pkt(0)
  if config['verbose']:
    print('Data received:',pkt.hex())
  op, pkt = pop(pkt,1)
  if op == CREATE:
    create(conn, pkt)
  elif op == GET:
    get(conn, pkt)
  elif op == EXOP: # unimplemented
    exop(conn, pkt)
  elif config['verbose']:
    print("unknown op: 0x%02x" % data[0])

  conn.close()
  os._exit(0)

def main():
    global config
    config = processcfg(getcfg('opaque-stored'))
    toprf.config = config

    socket.setdefaulttimeout(config['timeout'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((config['address'], config['port']))
    except socket.error as msg:
        print('Bind failed. Error Code : %s Message: %s' % (str(msg[0]), msg[1]))
        sys.exit()
    #Start listening on socket
    s.listen()
    kids = []
    try:
        # main loop
        while 1:
            #wait to accept a connection - blocking call
            try:
              conn, addr = s.accept()
            except socket.timeout:
              try:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid != 0:
                  print("remove pid", pid)
                  kids.remove(pid)
                continue
              except ChildProcessError:
                continue
            except:
              raise

            if config['verbose']:
                print('{} Connection from {}:{}'.format(datetime.datetime.now(), addr[0], addr[1]))

            while(len(kids)>config['max_kids']):
                pid, status = os.waitpid(0,0)
                kids.remove(pid)

            pid=os.fork()
            if pid==0:
              conn = NoiseWrapperServer(conn, config['noise_key'])
              try:
                handler(conn)
              except:
                print("fail")
                raise
              finally:
                try: conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                conn.close()
              sys.exit(0)
            else:
                kids.append(pid)

            try:
              pid, status = os.waitpid(-1,os.WNOHANG)
              if pid!=0:
                 kids.remove(pid)
            except ChildProcessError: pass

    except KeyboardInterrupt:
        pass
    s.close()

if __name__ == '__main__':
  main()
