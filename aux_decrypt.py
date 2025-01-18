import itertools
import string
import random
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
    return prefix + new_suffix

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
    grupo1='SecurityAESaaaaa'
    grupo2='SecurityAEShUFaa'
    grupo3='SecurityAESpFaaa'
    grupo4='SecurityAESxpFaa'
    grupo5='SecurityAESFaaaa'
    grupo6='SecurityAESMUFaa'
    grupo7='SecurityAESUFaaa'
    grupo8='SecurityAES2pFaa'
    flag_chave = False

    while not flag_chave:
        # Testa as chaves sequencialmente sem comparação direta
        if not flag_chave:
            flag_chave = testes_chaves(grupo1, ciphertext, found_results)
            grupo1 = next_key(grupo1)
            tested_keys += 1

        if not flag_chave:
            flag_chave = testes_chaves(grupo2, ciphertext, found_results)
            grupo2 = next_key(grupo2)
            tested_keys += 1

        if not flag_chave:
            flag_chave = testes_chaves(grupo3, ciphertext, found_results)
            grupo3 = next_key(grupo3)
            tested_keys += 1

        if not flag_chave:
            flag_chave = testes_chaves(grupo4, ciphertext, found_results)
            grupo4 = next_key(grupo4)
            tested_keys += 1

        if not flag_chave:
            flag_chave = testes_chaves(grupo5, ciphertext, found_results)
            grupo5 = next_key(grupo5)
            tested_keys += 1
            
        if not flag_chave:
            flag_chave = testes_chaves(grupo6, ciphertext, found_results)
            grupo6 = next_key(grupo6)
            tested_keys += 1

        if not flag_chave:
            flag_chave = testes_chaves(grupo7, ciphertext, found_results)
            grupo7 = next_key(grupo7)
            tested_keys += 1

        if not flag_chave:
            flag_chave = testes_chaves(grupo8, ciphertext, found_results)
            grupo8 = next_key(grupo8)
            tested_keys += 1


        # Exibe a cada 1 milhão de chaves testadas
        if tested_keys % 1000000 == 0:
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
    input_file = "arquivo-weak-0.in-full.hex"  # Substitua pelo caminho do arquivo de entrada
    output_file = "saida_weak.txt"  # Substitua pelo caminho do arquivo de saída

    main(input_file, output_file)
