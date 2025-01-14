import string

def salvar_chave_fraca(chave):
    with open('chaves_fracas.txt','a') as saida:
        saida.write(chave)
        saida.write('\n')

def salvar_chave_forte(chave):
    with open('chaves_fortes.txt','a') as saida:
        saida.write(chave)
        saida.write('\n')

# Função para gerar a próxima combinação dos 6 caracteres finais
def incrementar_chave_forte(chars, chave):
    parte_variavel = chave[8:]  # Parte variável da chave (últimos 6 caracteres)
    lista_chave = list(parte_variavel)
    i = len(lista_chave) - 1
    while i >= 0:
        if lista_chave[i] == chars[-1]:  # Último caractere do conjunto
            lista_chave[i] = chars[0]  # Volta para o primeiro caractere
            i -= 1
        else:
            lista_chave[i] = chars[chars.index(lista_chave[i]) + 1]
            break
    else:
        return None  # Não há mais combinações possíveis

    return chave[:8] + ''.join(lista_chave)  # Combina a parte fixa com a parte variável

# Função para gerar a próxima combinação dos 5 caracteres finais
def incrementar_chave_fraca(chars, chave):
    parte_variavel = chave[11:]  # Parte variável da chave
    lista_chave = list(parte_variavel)
    i = len(lista_chave) - 1
    while i >= 0:
        if lista_chave[i] == chars[-1]:  # Último caractere do conjunto
            lista_chave[i] = chars[0]  # Volta para o primeiro caractere
            i -= 1
        else:
            lista_chave[i] = chars[chars.index(lista_chave[i]) + 1]
            break
    else:
        return None  # Não há mais combinações possíveis

    return "SecurityAES" + ''.join(lista_chave)

# Conjunto de caracteres permitidos
chars = string.ascii_letters + string.digits

# Chave inicial
chave_inicial_fraca = "SecurityAES00000"
chave_inicial_forte = 'Security00000000'

while chave_inicial_fraca != "SecurityAESFFFFF":
    salvar_chave_fraca(chave_inicial_fraca)
    chave_inicial_fraca = incrementar_chave_fraca(chars, chave_inicial_fraca)

while chave_inicial_forte != "Security00FFFFFF":
    salvar_chave_forte(chave_inicial_forte)
    chave_inicial_forte = incrementar_chave_forte(chars, chave_inicial_forte)

salvar_chave_fraca(chave_inicial_fraca)
chave_inicial_fraca = incrementar_chave_fraca(chars, chave_inicial_fraca)
salvar_chave_forte(chave_inicial_forte)
chave_inicial_forte = incrementar_chave_forte(chars, chave_inicial_forte)