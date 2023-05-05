import os
import pkcs11

from pkcs11 import KeyType, Mechanism
from pkcs11.util import dsa

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='smartcard')

# Open a session on our token
with token.open(user_pin='secret') as session:
  # Generate an DSA keypair in this session
  public, private = session.generate_keypair(KeyType.DSA, 2048)

  # params = session.generate_domain_parameters(KeyType.DSA, 1024)
  # public, private = params.generate_keypair()

  # public key
  publicKey = dsa.encode_dsa_public_key(public)
  print("publicKey: 0x" + publicKey.hex())

  # address 
  address = session.digest(publicKey, mechanism=Mechanism.SHA_1)
  print("address: 0x" + address.hex())