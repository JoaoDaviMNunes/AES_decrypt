import itertools
import string
import multiprocessing
import time
from Crypto.Cipher import AES
from pathlib import Path

def e_legivel_ascii(texto):
    try:
        texto.decode('ascii')
        return True
    except UnicodeDecodeError:
        return False

def decifrar_com_chave(chave, cifra):
    cifra_aes = AES.new(chave.encode('utf-8'), AES.MODE_ECB)
    return cifra_aes.decrypt(cifra)

def processar_espaco_de_chaves(espaco_de_chaves, cifra, resultados_encontrados, id_grupo, intervalo=20):
    tempo_inicial = time.time()
    chaves_testadas = 0

    for sufixo_chave in espaco_de_chaves:
        chave = f"Security00{sufixo_chave}"
        try:
            texto_plano = decifrar_com_chave(chave, cifra)
            if e_legivel_ascii(texto_plano):
                texto_plano = texto_plano.decode('ascii')
                if any(palavra in texto_plano for palavra in ['codigo', 'Codigo', 'secreto', 'parabens', 'Parabens']):
                    resultados_encontrados.append((chave, texto_plano))
                    return  # Encerra o processamento ao encontrar a primeira chave válida
        except Exception:
            pass

        chaves_testadas += 1
        if chaves_testadas % 50000 == 0:
            tempo_decorrido = time.time() - tempo_inicial
            print(f"[Grupo {id_grupo}] Chaves testadas: {chaves_testadas}, Tempo decorrido: {tempo_decorrido:.2f}s, Chave atual: {chave}")

def dividir_espaco_de_chaves():
    caracteres = string.ascii_letters + string.digits
    return ("".join(combinacao) for combinacao in itertools.product(caracteres, repeat=6))

def principal():
    arquivo_entrada = "arquivo-strong-4.in-full.hex"
    arquivo_saida = "saida_strong.txt"
    num_processos = multiprocessing.cpu_count()

    cifra_hex = Path(arquivo_entrada).read_text().strip()
    cifra = bytes.fromhex(cifra_hex)

    espaco_de_chaves = list(dividir_espaco_de_chaves())
    tamanho_pedaco = len(espaco_de_chaves) // num_processos
    pedaços_de_chaves = [espaco_de_chaves[i:i + tamanho_pedaco] for i in range(0, len(espaco_de_chaves), tamanho_pedaco)]

    manager = multiprocessing.Manager()
    resultados_encontrados = manager.list()

    print(f"Iniciando a decifragem com {num_processos} processos.")

    processos = []
    for i, pedaco in enumerate(pedaços_de_chaves):
        processo = multiprocessing.Process(target=processar_espaco_de_chaves, args=(pedaco, cifra, resultados_encontrados, i))
        processos.append(processo)
        processo.start()

    for processo in processos:
        processo.join()

    with open(arquivo_saida, 'w') as f:
        for chave, texto_plano in resultados_encontrados:
            f.write(f"Chave: {chave}\nTexto plano: {texto_plano}\n\n")

    print("Decifragem concluída. Resultado salvo.")

if __name__ == "__main__":
    principal()
