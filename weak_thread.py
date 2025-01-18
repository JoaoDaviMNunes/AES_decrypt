import threading
import string
import time
from Crypto.Cipher import AES
from pathlib import Path

# Verifica se o texto pode ser decodificado como ASCII
def is_ascii_readable(text):
    try:
        text.decode('ascii')
        return True
    except UnicodeDecodeError:
        return False

# Descriptografa o texto cifrado com a chave fornecida usando o modo ECB do AES
def decrypt_with_key(key, ciphertext):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# Gera a próxima chave
def next_key(key):
    prefix = key[:11]
    suffix = key[11:]
    charset = string.ascii_letters + string.digits
    base = len(charset)
    number = 0
    for char in suffix:
        number = number * base + charset.index(char)
    number += 1
    new_suffix = ''
    while number > 0:
        new_suffix = charset[number % base] + new_suffix
        number //= base
    new_suffix = new_suffix.rjust(5, 'a')
    return prefix + new_suffix

# Função que testa chaves de um grupo específico
def test_keys_group(start_key, ciphertext, found_results, stop_event):
    current_key = start_key
    while not stop_event.is_set():
        try:
            plaintext = decrypt_with_key(current_key, ciphertext)
            if is_ascii_readable(plaintext):
                plaintext = plaintext.decode('ascii')
                if any(word in plaintext for word in ['codigo', 'Codigo', 'secreto', 'parabens', 'Parabens']):
                    found_results.append((current_key, plaintext))
                    print(f"Chave encontrada: {current_key}")
                    print(f"Texto Claro: {plaintext}")
                    stop_event.set()
                    return
        except Exception:
            pass
        current_key = next_key(current_key)

# Função principal que inicia a busca em paralelo
def busca_chave_parallel(ciphertext, found_results):
    start_time = time.time()
    tested_keys = 0

    # Chaves iniciais para cada grupo
    start_keys = [
        'SecurityAESaaaaa',
        'SecurityAESnaaaa',
        'SecurityAESAaaaa',
        'SecurityAESNaaaa',
        'SecurityAES0aaaa'
    ]

    threads = []
    stop_event = threading.Event()

    # Cria e inicia threads para cada grupo
    for start_key in start_keys:
        thread = threading.Thread(target=test_keys_group, args=(start_key, ciphertext, found_results, stop_event))
        threads.append(thread)
        thread.start()

    # Aguarda todas as threads terminarem
    for thread in threads:
        thread.join()

    elapsed = time.time() - start_time
    print(f"Concluído. Tempo decorrido: {elapsed:.2f}s")

# Função principal que inicia o processamento
def main(input_file, output_file):
    ciphertext_hex = Path(input_file).read_text().strip()
    ciphertext = bytes.fromhex(ciphertext_hex)

    found_results = []

    print("Iniciando a descriptografia...")

    busca_chave_parallel(ciphertext, found_results)

    with open(output_file, 'w') as f:
        for key, plaintext in found_results:
            f.write(f"Chave: {key}\nTexto claro: {plaintext}\n\n")

    print("Descriptografia concluída. Resultados salvos.")

if __name__ == "__main__":
    input_file = "arquivo-weak-4.in-full.hex"  # Substitua pelo caminho do arquivo de entrada
    output_file = "saida_weak.txt"  # Substitua pelo caminho do arquivo de saída

    main(input_file, output_file)
