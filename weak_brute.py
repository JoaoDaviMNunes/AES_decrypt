import itertools
import string
import multiprocessing
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

# Processa um espaço de chaves (key space) tentando descriptografar o texto cifrado e verificando se contém palavras-chave
def process_key_space(key_space, ciphertext, found_results, group_id):
    start_time = time.time()
    tested_keys = 0

    for key_suffix in key_space:
        key = f"SecurityAES{key_suffix}"
        try:
            plaintext = decrypt_with_key(key, ciphertext)
            if is_ascii_readable(plaintext):
                plaintext = plaintext.decode('ascii')
                # Verifica se o texto contém alguma das palavras-chave e, se sim, adiciona aos resultados encontrados e para o processamento
                if any(word in plaintext for word in ['codigo', 'Codigo', 'secreto', 'parabens', 'Parabens']):
                    found_results.append((key, plaintext))
                    print(f"Chave encontrada: {key}")
                    return
        except Exception:
            pass

        tested_keys += 1
        if tested_keys % 50000 == 0:
            elapsed = time.time() - start_time
            print(f"[Grupo {group_id}] Chaves testadas: {tested_keys}, Tempo decorrido: {elapsed:.2f}s")

    elapsed = time.time() - start_time
    print(f"[Grupo {group_id}] Concluído. Total de chaves testadas: {tested_keys}, Tempo decorrido: {elapsed:.2f}s")

# Divide o espaço de chaves em combinações de 5 caracteres alfanuméricos
def divide_key_space():
    characters = string.ascii_letters + string.digits
    key_space = ("".join(comb) for comb in itertools.product(characters, repeat=5))
    return list(key_space)

# Função principal que configura o ambiente de multiprocessing e inicia o processamento
def main(input_file, output_file, num_processes):
    ciphertext_hex = Path(input_file).read_text().strip()
    ciphertext = bytes.fromhex(ciphertext_hex)

    key_space = divide_key_space()
    chunk_size = len(key_space) // num_processes
    key_chunks = [key_space[i:i + chunk_size] for i in range(0, len(key_space), chunk_size)]

    manager = multiprocessing.Manager()
    found_results = manager.list()

    print(f"Iniciando a descriptografia com {num_processes} processos.")

    processes = []
    for i, chunk in enumerate(key_chunks):
        process = multiprocessing.Process(target=process_key_space, args=(chunk, ciphertext, found_results, i))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    with open(output_file, 'w') as f:
        for key, plaintext in found_results:
            f.write(f"Chave: {key}\nTexto claro: {plaintext}\n\n")

    print("Descriptografia concluída. Resultados salvos.")

if __name__ == "__main__":
    input_file = "arquivo-weak-4.in-full.hex"  # Substitua pelo caminho do arquivo de entrada
    output_file = "saida_weak.txt"  # Substitua pelo caminho do arquivo de saída
    num_processes = multiprocessing.cpu_count()  # Use o número de CPUs disponíveis

    main(input_file, output_file, num_processes)
