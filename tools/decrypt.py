from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad


def generate_keys(base_key):
    key = base_key.encode("utf-8")
    if len(key) < 8:
        key = key.ljust(8, b"\0")
    return key[:8]


def decrypt_des(ciphertext, base_key):
    key = generate_keys(base_key)
    cipher = DES.new(key, DES.MODE_ECB)
    try:
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, DES.block_size)
        return plaintext.decode("utf-8", errors="ignore")
    except ValueError as e:
        print(f"Failed to decrypt with key {base_key}: {e}")
        return None


ciphertext = bytes.fromhex("xxxxxxx")
base_key = "xxxxx"

decrypted_text = decrypt_des(ciphertext, base_key)
if decrypted_text:
    print(f"Decrypted text: {decrypted_text}")
