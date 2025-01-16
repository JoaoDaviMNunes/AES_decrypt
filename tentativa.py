import itertools
import string
import multiprocessing
import time
from Crypto.Cipher import AES
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

def process_key_space(key_space, ciphertext, found_results, group_id):
    start_time = time.time()
    tested_keys = 0

    for key_suffix in key_space:
        key = f"SecurityAES{key_suffix}"
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

def divide_key_space():
    characters = string.ascii_letters + string.digits
    key_space = ("".join(comb) for comb in itertools.product(characters, repeat=5))
    return list(key_space)

def main(input_file, output_file, num_processes):
    ciphertext_hex = Path(input_file).read_text().strip()
    ciphertext = bytes.fromhex(ciphertext_hex)

    key_space = divide_key_space()
    chunk_size = len(key_space) // num_processes
    key_chunks = [key_space[i:i + chunk_size] for i in range(0, len(key_space), chunk_size)]

    manager = multiprocessing.Manager()
    found_results = manager.list()

    print(f"Starting decryption with {num_processes} processes.")

    processes = []
    for i, chunk in enumerate(key_chunks):
        process = multiprocessing.Process(target=process_key_space, args=(chunk, ciphertext, found_results, i))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    with open(output_file, 'w') as f:
        for key, plaintext in found_results:
            f.write(f"Key: {key}\nPlaintext: {plaintext}\n\n")

    print("Decryption completed. Results saved.")

if __name__ == "__main__":
    input_file = "arquivo-weak-4.in-full.hex"  # Substitua pelo caminho do arquivo de entrada
    output_file = "decrypted_results.txt"  # Substitua pelo caminho do arquivo de saída
    num_processes = multiprocessing.cpu_count()  # Use o número de CPUs disponíveis

    main(input_file, output_file, num_processes)
