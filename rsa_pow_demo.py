"""Independent RSA + POW demo.

Steps:
- Generate RSA key pair
- Find a nonce so sha256(nickname + nonce) starts with four zeros
- Sign the payload with the private key
- Verify with the public key (and show a failed tamper check)
"""

import base64
import hashlib
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def find_pow(nickname: str, zero_count: int = 4, start_nonce: int = 0):
    target = "0" * zero_count
    nonce = start_nonce
    start = time.perf_counter()
    while True:
        payload = f"{nickname}{nonce}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if digest.startswith(target):
            return payload, digest, nonce, time.perf_counter() - start
        nonce += 1


def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def sign(private_key, message: str) -> bytes:
    return private_key.sign(
        message.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify(public_key, message: str, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def export_pem(private_key, public_key):
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


def main():
    nickname = "JackFrost"

    payload, digest, nonce, elapsed = find_pow(nickname, zero_count=4)
    print(f"POW: {digest} payload='{payload}' nonce={nonce} time={elapsed:.3f}s")

    private_key, public_key = generate_rsa_keypair()
    priv_pem, pub_pem = export_pem(private_key, public_key)
    print("Private key (PEM):")
    print(priv_pem)
    print("Public key (PEM):")
    print(pub_pem)

    signature = sign(private_key, payload)
    print(f"Signature (base64): {base64.b64encode(signature).decode('ascii')}")

    print(f"Verify original payload: {verify(public_key, payload, signature)}")
    print(f"Verify tampered payload: {verify(public_key, payload + 'x', signature)}")


if __name__ == "__main__":
    main()
