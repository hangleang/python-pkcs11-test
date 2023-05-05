import os
import pkcs11

from pkcs11 import KeyType, Attribute, Mechanism
from pkcs11.util import dh

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='smartcard')

# Open a session on our token
with token.open(user_pin='secret') as session:
  # Generate an DH keypair in this session
  params = session.generate_domain_parameters(KeyType.DH, 512)
  public, private = params.generate_keypair()

  # This is the public key
  publicKey = dh.encode_dh_public_key(public)
  print("publicKey: 0x" + publicKey.hex())

  # address 
  address = session.digest(publicKey, mechanism=Mechanism.SHA_1)
  print("address: 0x" + address.hex())

  # # deriving shared key
  # Given our DH private key `private` and the other party's public key `other_public`
  other_public, other_private = params.generate_keypair()
  key = private.derive_key(
    KeyType.AES, 128,
    mechanism_param=other_public[Attribute.VALUE],
    template={
      Attribute.SENSITIVE: False,
      Attribute.EXTRACTABLE: True,
    })
  
  # shared secret key
  print("sharedKey: " + key[Attribute.VALUE].hex())

