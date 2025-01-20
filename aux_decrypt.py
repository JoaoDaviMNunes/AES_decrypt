import string
import time
import threading
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

# Gera a próxima chave com base em um sufixo dinâmico
def next_key(suffix):
    charset = string.ascii_letters + string.digits
    base = len(charset)
    number = 0

    # Converte o sufixo em um número usando a base 62
    for char in suffix:
        number = number * base + charset.index(char)

    # Incrementa o número
    number += 1

    # Converte de volta para a string de sufixo
    new_suffix = ''
    while number > 0:
        new_suffix = charset[number % base] + new_suffix
        number //= base

    # Garante que o novo sufixo tenha 6 caracteres (preenche com 'a' se necessário)
    new_suffix = new_suffix.rjust(6, 'a')

    return new_suffix

# Testa uma chave e verifica se o texto descriptografado contém palavras-chave
def test_key(prefix, suffix, ciphertext, found_results):
    key = prefix + suffix
    try:
        plaintext = decrypt_with_key(key, ciphertext)
        if is_ascii_readable(plaintext):
            plaintext = plaintext.decode('ascii')
            if any(word in plaintext for word in ['codigo', 'Codigo', 'secreto', 'parabens', 'Parabens']):
                found_results.append((key, plaintext))
                print(f"Chave encontrada: {key}")
                print(f"Texto Claro: {plaintext}")
                return True
    except Exception:
        pass
    return False

# Função para processar um grupo de sufixos
def process_group(prefix, group_start, ciphertext, found_results, stop_flag):
    current_suffix = group_start
    while not stop_flag.is_set():
        if test_key(prefix, current_suffix, ciphertext, found_results):
            stop_flag.set()  # Interrompe outras threads ao encontrar a chave correta
            break
        current_suffix = next_key(current_suffix)

# Função principal de busca por chaves com multithreading
def busca_chave(ciphertext, found_results):
    prefix = 'Security00'
    charset = string.ascii_letters + string.digits

    groups = [
        'aaaaaa', 'eiqHei', 'iqHeiq', 'myXLmy', 'qHeiqG',
        'uPuPuO', 'yXLmyW', 'C51TC4', 'HeiqHc', 'LmyXLk',
        'PuPuPs', 'TC51TA', 'XLmyXI', '1TC51Q', '51TC5Y'
    ]

    start_time = time.time()
    stop_flag = threading.Event()  # Sinalização para interromper threads

    threads = []
    for group_start in groups:
        thread = threading.Thread(target=process_group, args=(prefix, group_start, ciphertext, found_results, stop_flag))
        threads.append(thread)
        thread.start()

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

    busca_chave(ciphertext, found_results)

    with open(output_file, 'w') as f:
        for key, plaintext in found_results:
            f.write(f"Chave: {key}\nTexto claro: {plaintext}\n\n")

    print("Descriptografia concluída. Resultados salvos.")

if __name__ == "__main__":
    input_file = "arquivo-weak-4.in-full.hex"  # Substitua pelo caminho do arquivo de entrada
    output_file = "saida_weak.txt"  # Substitua pelo caminho do arquivo de saída

    main(input_file, output_file)
