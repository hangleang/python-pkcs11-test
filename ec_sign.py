import os
import pkcs11

from pkcs11 import KeyType, Attribute, Mechanism
from pkcs11.util import ec

# Initialise our PKCS#11 library
lib = pkcs11.lib(os.environ['PKCS11_MODULE'])
token = lib.get_token(token_label='smartcard')

msg = b'MESSAGE'

# Open a session on our token
with token.open(user_pin='secret') as session:
  # Generate an DH keypair in this session
  params = session.create_domain_parameters(KeyType.EC, {
    Attribute.EC_PARAMS: ec.encode_named_curve_parameters('secp256k1')
  }, local=True)
  public, private = params.generate_keypair()

  # This is the public key
  publicKey = ec.encode_ec_public_key(public)
  print("publicKey: 0x" + publicKey.hex())

  # hash publicKey (32 bytes) into address (20 bytes)
  # in ethereum, use SHA3 (keccak256) to derive publicKey into address
  address = session.digest(publicKey, mechanism=Mechanism.SHA_1)
  print("address: 0x" + address.hex())

  # hash msg or txn (any abitrary bytes) into msgHash or txHash (32 bytes)
  msgHash = session.digest(msg, mechanism=Mechanism.SHA256)
  print("msgHash: 0x" + msgHash.hex())

  # sign `msgHash` with `private`
  sig = private.sign(msgHash, mechanism=Mechanism.ECDSA)
  # below mechanism: hash `msg` then sign `hashed` with `private`
  # sig = private.sign(msg, mechanism=Mechanism.ECDSA_SHA512)

  # encode into hex, split signature into r, s value
  print("signature: 0x" + ec.encode_ecdsa_signature(sig).hex())
  n = int(len(sig) / 2)
  split_sig = [sig[i:i+n] for i in range(0, len(sig), n)]
  print(f"r: 0x{split_sig[0].hex()}\ns: 0x{split_sig[1].hex()}\n")

  # verify `sig` with `public` key
  assert public.verify(msgHash, sig, mechanism=Mechanism.ECDSA)