from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import multiprocessing


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
    except ValueError:
        return None


def is_valid_plaintext(plaintext):
    return len(plaintext) > 0 and all(
        32 <= ord(c) <= 126 or c == "\n" for c in plaintext
    )


def save_key_to_file(key, decrypted_text, filename="keys.txt"):
    with open(filename, "a") as f:
        f.write(f"Key: {key}\nDecrypted Text: {decrypted_text}\n\n")


def brute_force_decrypt_range(start, end, ciphertext):
    valid_keys = []
    for i in range(start, end):
        base_key = str(i).zfill(8)
        decrypted_text = decrypt_des(ciphertext, base_key)

        if decrypted_text and is_valid_plaintext(decrypted_text):
            print(f"Found valid key: {base_key}")
            save_key_to_file(base_key, decrypted_text)
            valid_keys.append((base_key, decrypted_text))
    return valid_keys


def main():
    ciphertext = bytes.fromhex("xxxxxxxxxx")
    total_keys = 100000000
    num_processes = multiprocessing.cpu_count()

    keys_per_process = total_keys // num_processes
    ranges = []
    for i in range(num_processes):
        start = i * keys_per_process
        end = (i + 1) * keys_per_process if i < num_processes - 1 else total_keys
        ranges.append((start, end))

    pool = multiprocessing.Pool(num_processes)
    results = pool.starmap(
        brute_force_decrypt_range, [(start, end, ciphertext) for start, end in ranges]
    )

    valid_keys = [key for result in results for key in result]

    if valid_keys:
        print(
            f"{len(valid_keys)} valid keys and decrypted texts have been saved to 'keys.txt'."
        )
    else:
        print("Decryption failed.")


if __name__ == "__main__":
    main()
