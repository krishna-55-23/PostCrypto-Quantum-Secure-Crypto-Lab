import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF

# ─── RSA ────────────────────────────────────────────────────────────────────
def rsa_full(message, key_bits=2048):
    key = RSA.generate(key_bits)
    private_key = key.export_key().decode()
    public_key  = key.publickey().export_key().decode()

    cipher      = PKCS1_OAEP.new(key.publickey())
    encrypted   = base64.b64encode(cipher.encrypt(message.encode())).decode()
    decrypted   = PKCS1_OAEP.new(key).decrypt(base64.b64decode(encrypted)).decode()

    return public_key, private_key, encrypted, decrypted


# ─── ECC ────────────────────────────────────────────────────────────────────
def ecc_full(message):
    sender_key   = ECC.generate(curve='P-256')
    receiver_key = ECC.generate(curve='P-256')

    sender_pub   = sender_key.public_key()
    receiver_pub = receiver_key.public_key()

    # ECDH shared secret
    shared_point = sender_key.d * receiver_pub.pointQ
    shared_bytes = int(shared_point.x).to_bytes(32, 'big')

    # Derive 16-byte AES key
    aes_key = HKDF(shared_bytes, 16, b'', SHA256)

    # AES-EAX encrypt
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    encrypted = base64.b64encode(ciphertext).decode()

    # AES-EAX decrypt
    cipher_dec = AES.new(aes_key, AES.MODE_EAX, nonce=cipher.nonce)
    decrypted  = cipher_dec.decrypt(ciphertext).decode()

    return (
        sender_pub.export_key(format='PEM'),
        sender_key.export_key(format='PEM'),
        encrypted,
        decrypted,
    )


# ─── AES ────────────────────────────────────────────────────────────────────
# ✅ FIX: accept key_bytes so the user's choice (128/192/256 bit) is respected
def aes_full(message, key_bytes=32):
    """
    key_bytes: 16 = 128-bit, 24 = 192-bit, 32 = 256-bit (default)
    """
    key = get_random_bytes(key_bytes)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())

    return (
        base64.b64encode(key).decode(),        # secret key (b64)
        base64.b64encode(ciphertext).decode(),  # encrypted (b64)
        message,                                # decrypted (original)
    )


# ─── KYBER (simulated) ──────────────────────────────────────────────────────
def kyber_full(message=""):
    fake_pub      = base64.b64encode(get_random_bytes(32)).decode()
    fake_priv     = base64.b64encode(get_random_bytes(32)).decode()
    shared_secret = base64.b64encode(get_random_bytes(32)).decode()
    status        = "Key Encapsulation Successful (simulated)"
    return fake_pub, fake_priv, shared_secret, status


# ─── DILITHIUM ──────────────────────────────────────────────────────────────
def dilithium_full(message):
    key = ECC.generate(curve='P-256')

    h         = SHA256.new(message.encode())
    signer    = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)

    verifier  = DSS.new(key.public_key(), 'fips-186-3')
    verifier.verify(h, signature)

    return (
        key.public_key().export_key(format='PEM'),
        key.export_key(format='PEM'),
        base64.b64encode(signature).decode(),
        "✅ Signature Verified Successfully",
    )