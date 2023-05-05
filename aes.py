import os
import pkcs11

from pkcs11 import KeyType, Attribute

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='smartcard')

data = b'INPUT DATA'

# Open a session on our token
with token.open(user_pin='secret') as session:
  # Generate an AES key in this session, enable below template if want to extract the key
  key = session.generate_key(KeyType.AES, 256, 
    # template={
    #   Attribute.SENSITIVE: False,
    #   Attribute.EXTRACTABLE: True,
    # }
  )
  # # This is the secret key
  # print(key[Attribute.VALUE].hex())

  # generate IV, encryption, decryption
  iv = session.generate_random(128)  # AES blocks are fixed at 128 bits
  ciphertext = key.encrypt(data, mechanism_param=iv)
  plaintext = key.decrypt(ciphertext, mechanism_param=iv)
  assert plaintext == data
