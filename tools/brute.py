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
        return None


def is_valid_plaintext(plaintext):
    return len(plaintext) > 0 and all(
        32 <= ord(c) <= 126 or c == "\n" for c in plaintext
    )


def save_key_to_file(key, decrypted_text, filename="keys.txt"):
    with open(filename, "a") as f:
        f.write(f"Key: {key}\nDecrypted Text: {decrypted_text}\n\n")


def brute_force_decrypt(ciphertext):
    for i in range(100000000):
        base_key = str(i).zfill(8)
        decrypted_text = decrypt_des(ciphertext, base_key)

        if decrypted_text and is_valid_plaintext(decrypted_text):
            print(f"Found valid key: {base_key}")
            save_key_to_file(base_key, decrypted_text)


ciphertext = bytes.fromhex("xxxxxxxxx")

brute_force_decrypt(ciphertext)
