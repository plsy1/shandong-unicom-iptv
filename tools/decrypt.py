from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def generate_keys(base_key):
    key = base_key.encode("utf-8")
    if len(key) < 8:
        key = key.ljust(8, b"\0")
    return key + key + key


def decrypt_3des(ciphertext, base_key):
    key = generate_keys(base_key)

    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode("utf-8", errors="ignore")
    except ValueError as e:
        print(f"Failed to decrypt with key {base_key}: {e}")
        return None

## 密文
ciphertext = bytes.fromhex("xxxxxx")

## 密钥
base_key = "62226000"

decrypted_text = decrypt_3des(ciphertext, base_key)
print(f"Decrypted text: {decrypted_text}")
