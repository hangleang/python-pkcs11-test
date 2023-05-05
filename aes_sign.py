import os
import pkcs11

from pkcs11 import KeyType, Mechanism

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='smartcard')

data = b'INPUT DATA'

# Open a session on our token
with token.open(user_pin='secret') as session:
  # Generate an AES key in this session
  key = session.generate_keypair(KeyType.AES, 256) 

  # sign/verify with `key`
  signature = key.sign(data, mechanism=Mechanism.AES_MAC)
  assert key.verify(data, signature)