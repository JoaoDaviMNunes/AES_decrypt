import string

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

# Exemplo de uso
current_key = "SecurityAESa9999"

i = 0
while i < 100:
    current_key = next_key(current_key)
    print(current_key)
    i += 1
