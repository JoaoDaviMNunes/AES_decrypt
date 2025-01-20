import string
import time
from Crypto.Cipher import AES
from pathlib import Path

# Verifica se o texto pode ser decodificado como ASCII
def e_ascii_legivel(texto):
    try:
        texto.decode('ascii')
        return True
    except UnicodeDecodeError:
        return False

# Descriptografa o texto cifrado com a chave fornecida usando o modo ECB do AES
def descriptografar_com_chave(chave, texto_cifrado):
    cifrador = AES.new(chave.encode('utf-8'), AES.MODE_ECB)
    return cifrador.decrypt(texto_cifrado)

# Gera a próxima chave
def proxima_chave(chave):
    # Os 11 primeiros caracteres são conhecidos
    prefixo = chave[:11]
    # Os últimos 5 caracteres são desconhecidos
    sufixo = chave[11:]
    
    # Conjunto de caracteres permitidos: letras maiúsculas, letras minúsculas e dígitos
    conjunto_caracteres = string.ascii_letters + string.digits
    
    # Converte o sufixo em um número usando a base 62
    base = len(conjunto_caracteres)
    numero = 0
    for char in sufixo:
        numero = numero * base + conjunto_caracteres.index(char)
    
    # Incrementa o número
    numero += 1
    
    # Converte de volta para a string de sufixo
    novo_sufixo = ''
    while numero > 0:
        novo_sufixo = conjunto_caracteres[numero % base] + novo_sufixo
        numero //= base
    
    # Garante que o novo sufixo tenha 5 caracteres (preenche com 'a' se necessário)
    novo_sufixo = novo_sufixo.rjust(5, 'a')
    
    # Retorna a nova chave
    return novo_sufixo

def realizar_testes_chaves(chave, texto_cifrado, resultados_encontrados):
    try:
        texto_plano = descriptografar_com_chave(chave, texto_cifrado)
        if e_ascii_legivel(texto_plano):
            texto_plano = texto_plano.decode('ascii')
            # Verifica se o texto contém alguma das palavras-chave e, se sim, adiciona aos resultados encontrados e sinaliza para parar os processos
            if any(palavra in texto_plano for palavra in ['codigo', 'Codigo', 'secreto', 'parabens', 'Parabens']):
                resultados_encontrados.append((chave, texto_plano))
                print(f"Chave encontrada: {chave}")
                print(f"Texto Claro: {texto_plano}")
                return True
    except Exception:
        pass
    return False

# Processa um espaço de chaves (key space) tentando descriptografar o texto cifrado e verificando se contém palavras-chave
def buscar_chave(texto_cifrado, resultados_encontrados):
    tempo_inicio = time.time()
    chaves_testadas = 0
    prefixo = 'SecurityAES'
    grupo_chaves = [
        'aaaaa','naaaa','Aaaaa','Naaaa','0aaaa'
    ]
    chave_encontrada = False
    max_chaves = 62**5

    while not chave_encontrada or chaves_testadas < max_chaves:
        for i in range(len(grupo_chaves)):
            if not chave_encontrada:
                chave_encontrada = realizar_testes_chaves(prefixo + grupo_chaves[i], texto_cifrado, resultados_encontrados)
                grupo_chaves[i] = proxima_chave(grupo_chaves[i])
                chaves_testadas += 1

        # Exibe a cada 1 milhão de chaves testadas
        if chaves_testadas % 1000000 < len(grupo_chaves):
            tempo_decorrido = time.time() - tempo_inicio
            print(f"Chaves testadas: {chaves_testadas}, Tempo decorrido: {tempo_decorrido:.2f}s")

    tempo_decorrido = time.time() - tempo_inicio
    print(f"Concluído. Total de chaves testadas: {chaves_testadas}, Tempo decorrido: {tempo_decorrido:.2f}s")


# Função principal que inicia o processamento
def principal(arquivo_entrada, arquivo_saida):
    texto_cifrado_hex = Path(arquivo_entrada).read_text().strip()
    texto_cifrado = bytes.fromhex(texto_cifrado_hex)

    resultados_encontrados = []

    print("Iniciando a descriptografia...")

    buscar_chave(texto_cifrado, resultados_encontrados)

    with open(arquivo_saida, 'w') as f:
        for chave, texto_plano in resultados_encontrados:
            f.write(f"Chave: {chave}\nTexto claro: {texto_plano}\n\n")

    print("Descriptografia concluída. Resultados salvos.")

if __name__ == "__main__":
    arquivo_entrada = "arquivo-weak-4.in-full.hex"  # Substitua pelo caminho do arquivo de entrada
    arquivo_saida = "saida_weak.txt"  # Substitua pelo caminho do arquivo de saída

    principal(arquivo_entrada, arquivo_saida)
