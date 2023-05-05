import os
import pkcs11

from pkcs11 import KeyType, Attribute, Mechanism, KDF
from pkcs11.util import ec

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='smartcard')

# Open a session on our token
with token.open(user_pin='secret', rw=True) as session:
  # Generate an DH keypair in this session
  params = session.create_domain_parameters(KeyType.EC, {
    Attribute.EC_PARAMS: ec.encode_named_curve_parameters('secp256k1')
  }, local=True)
  public, private = params.generate_keypair(store=True, label="signKey")

  # the public key
  publicKey = ec.encode_ec_public_key(public)
  print("publicKey: 0x" + publicKey.hex())

  # address
  address = session.digest(publicKey, mechanism=Mechanism.SHA_1)
  print("address: 0x" + address.hex())

  # deriving shared key
  # Given our DH private key `private` and the other party's public key `other_public`
  other_public, other_private = params.generate_keypair()
  key = private.derive_key(
    KeyType.AES, 128,
    mechanism_param=(KDF.NULL, None, other_public[Attribute.EC_POINT]),
    template={
      Attribute.SENSITIVE: False,
      Attribute.EXTRACTABLE: True,
    }
  ) 

  # the shared secret key
  print("sharedKey: " + key[Attribute.VALUE].hex())