import os
import pkcs11

from pkcs11 import KeyType, Attribute, Mechanism, ObjectClass
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

  # encrypt/decrypt
  ciphertext = public.encrypt(data)
  plaintext = private.decrypt(ciphertext)
  assert plaintext == data

  # wrap/unwrap
  # Given a public key, `public`, and a secret key `key`, we can extract an encrypted version of `key`
  # NOTE: template here is used to verifying only
  key = session.generate_key(KeyType.AES, 256, template={ Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False })
  crypttext = public.wrap_key(key)
  unwrapped_key = private.unwrap_key(ObjectClass.SECRET_KEY, KeyType.AES, crypttext, template={ Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False })
  # print(key[Attribute.VALUE].hex())
  # print(unwrapped_key[Attribute.VALUE].hex())
  assert unwrapped_key[Attribute.VALUE] == key[Attribute.VALUE]