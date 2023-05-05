import os
import pkcs11

from pkcs11 import KeyType, Mechanism
from pkcs11.util import rsa

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='smartcard')

data = b'INPUT DATA'

# Open a session on our token
with token.open(user_pin='secret') as session:
  # Generate an RSA keypair in this session
  public, private = session.generate_keypair(KeyType.RSA, 2048)

  # public key
  publicKey = rsa.encode_rsa_public_key(public)
  print("publicKey: 0x" + publicKey.hex())

  # address
  address = session.digest(publicKey, mechanism=Mechanism.SHA_1)
  print("address: 0x" + address.hex())

  # sign/verify
  signature = private.sign(data)
  assert public.verify(data, signature)
  