import os
import pkcs11

from pkcs11 import KeyType, Attribute, ObjectClass, Mechanism

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='smartcard')

data = b'INPUT DATA'

# Open a session on our token
with token.open(user_pin='secret') as session:
  # non-sensitive, extractable
  # template = {
  #   Attribute.SENSITIVE: False,
  #   Attribute.EXTRACTABLE: True,
  # } 

  # Generate an DES2/3 key in this session
  des2 = session.generate_key(
    KeyType.DES2, 
    # template=template
  )
  des3 = session.generate_key(
    KeyType.DES3, 
    # template=template
  )

  # # This is the secret key
  # print(des2[Attribute.VALUE].hex())
  # print(des3[Attribute.VALUE].hex())

  # Given an DES3 key 
  iv = session.generate_random(64)
  ciphertext = des3.encrypt(data, mechanism_param=iv)
  plaintext = des3.decrypt(ciphertext, mechanism_param=iv)
  assert plaintext == data
