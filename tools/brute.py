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


def is_valid_plaintext(plaintext):
    return len(plaintext) > 0 and all(
        32 <= ord(c) <= 126 or c == "\n" for c in plaintext
    )


def brute_force_decrypt(ciphertext):
    for i in range(100000000):
        base_key = str(i).zfill(8)
        decrypted_text = decrypt_3des(ciphertext, base_key)

        if decrypted_text and is_valid_plaintext(decrypted_text):
            print(f"Decrypted with key {base_key}: {decrypted_text}")
            return base_key, decrypted_text
    return None, None


ciphertext = bytes.fromhex("xxxxx")

key, decrypted_text = brute_force_decrypt(ciphertext)

if key:
    print(f"Correct key: {key}")
    print(f"Decrypted text: {decrypted_text}")
else:
    print("Decryption failed.")
