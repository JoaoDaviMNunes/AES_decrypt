import itertools
import string
import random
import time
from Crypto.Cipher import AES
from pathlib import Path
import concurrent.futures

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
    # Os 11 primeiros caracteres são conhecidos
    prefix = key[:11]
    # Os últimos 5 caracteres são desconhecidos
    suffix = key[11:]
    
    # Conjunto de caracteres permitidos: letras maiúsculas, letras minúsculas e dígitos
    charset = string.ascii_letters + string.digits
    
    # Converte o sufixo em um número usando a base 62
    base = len(charset)
    number = 0
    for char in suffix:
        number = number * base + charset.index(char)
    
    # Incrementa o número
    number += 1
    
    # Converte de volta para a string de sufixo
    new_suffix = ''
    while number > 0:
        new_suffix = charset[number % base] + new_suffix
        number //= base
    
    # Garante que o novo sufixo tenha 5 caracteres (preenche com 'a' se necessário)
    new_suffix = new_suffix.rjust(5, 'a')
    
    # Retorna a nova chave
    return new_suffix

def testes_chaves(key, ciphertext, found_results):
    try:
        plaintext = decrypt_with_key(key, ciphertext)
        if is_ascii_readable(plaintext):
            plaintext = plaintext.decode('ascii')
            # Verifica se o texto contém alguma das palavras-chave e, se sim, adiciona aos resultados encontrados e sinaliza para parar os processos
            if any(word in plaintext for word in ['codigo', 'Codigo', 'secreto', 'parabens', 'Parabens']):
                found_results.append((key, plaintext))
                print(f"Chave encontrada: {key}")
                print(f"Texto Claro: {plaintext}")
                return True
    except Exception:
        pass
    return False

# Processa um espaço de chaves (key space) tentando descriptografar o texto cifrado e verificando se contém palavras-chave
def busca_chave(ciphertext, found_results):
    start_time = time.time()
    tested_keys = 0
    prefixo = 'SecurityAES'
    grupo_chaves = [
        'aaaaa','naaaa','Aaaaa','Naaaa','0aaaa'
    ]
    flag_chave = False
    max_chaves = 62**5

    with concurrent.futures.ThreadPoolExecutor() as executor:
        while not flag_chave and tested_keys < max_chaves:
            futures = []
            for i in range(len(grupo_chaves)):
                if not flag_chave:
                    # Inicia cada chave em uma thread separada
                    futures.append(executor.submit(testes_chaves, prefixo + grupo_chaves[i], ciphertext, found_results))
                    grupo_chaves[i] = next_key(grupo_chaves[i])
                    tested_keys += 1

            # Verifica se algum thread encontrou a chave
            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    flag_chave = True

            # Exibe a cada 1 milhão de chaves testadas
            if tested_keys % 1000000 < len(grupo_chaves):
                elapsed = time.time() - start_time
                print(f"Chaves testadas: {tested_keys}, Tempo decorrido: {elapsed:.2f}s")

    elapsed = time.time() - start_time
    print(f"Concluído. Total de chaves testadas: {tested_keys}, Tempo decorrido: {elapsed:.2f}s")


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
    output_file = "saida_weak_thread.txt"  # Substitua pelo caminho do arquivo de saída

    main(input_file, output_file)
