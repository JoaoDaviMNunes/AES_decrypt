from Crypto.Cipher import AES
import binascii
import string
import multiprocessing
import time
import itertools
from pathlib import Path

def is_ascii_readable(text):
    try:
        text.decode('ascii')
        return True
    except UnicodeDecodeError:
        return False

def decrypt_with_key(key, ciphertext):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def process_key_space(start, end, characters, ciphertext, found_results, group_id):
    start_time = time.time()
    tested_keys = 0

    for key_suffix in itertools.islice(itertools.product(characters, repeat=5), start, end):
        key = f"SecurityAES{''.join(key_suffix)}"
        try:
            plaintext = decrypt_with_key(key, ciphertext)
            if is_ascii_readable(plaintext):
                plaintext = plaintext.decode('ascii')
                if any(word in plaintext for word in ['codigo', 'Codigo', 'secreto', 'parabens', 'Parabens']):
                    found_results.append((key, plaintext))
        except Exception:
            pass

        tested_keys += 1
        if tested_keys % 1000 == 0:
            elapsed = time.time() - start_time
            print(f"[Group {group_id}] Keys tested: {tested_keys}, Time elapsed: {elapsed:.2f}s")

    elapsed = time.time() - start_time
    print(f"[Group {group_id}] Completed. Total keys tested: {tested_keys}, Time elapsed: {elapsed:.2f}s")

def divide_key_space(num_processes, total_combinations):
    chunk_size = total_combinations // num_processes
    ranges = [(i * chunk_size, (i + 1) * chunk_size) for i in range(num_processes)]
    ranges[-1] = (ranges[-1][0], total_combinations)  # Ensure the last range covers all remaining combinations
    return ranges

def main(input_file, output_file, num_processes):
    ciphertext_hex = Path(input_file).read_text().strip()
    ciphertext = bytes.fromhex(ciphertext_hex)

    characters = string.ascii_letters + string.digits
    total_combinations = len(characters) ** 5

    ranges = divide_key_space(num_processes, total_combinations)

    manager = multiprocessing.Manager()
    found_results = manager.list()

    print(f"Starting decryption with {num_processes} processes.")

    processes = []
    for i, (start, end) in enumerate(ranges):
        process = multiprocessing.Process(target=process_key_space, args=(start, end, characters, ciphertext, found_results, i))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    with open(output_file, 'w') as f:
        for key, plaintext in found_results:
            f.write(f"Key: {key}\nPlaintext: {plaintext}\n\n")

    print("Decryption completed. Results saved.")

if __name__ == "__main__":
    input_file = "arquivo-weak-4.in-full.hex"  # Replace with the path to the input file
    output_file = "decrypted_results.txt"  # Replace with the path to the output file
    num_processes = multiprocessing.cpu_count()  # Use the number of available CPUs

    main(input_file, output_file, num_processes)
