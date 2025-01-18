import string

# Definindo o conjunto de caracteres para base 62 (letras maiúsculas, minúsculas e dígitos)
charset = string.ascii_letters + string.digits  # 62 caracteres possíveis

# Função para incrementar a chave no formato base62 (apenas para os últimos 6 caracteres)
def increment_key(key):
    base = len(charset)
    key_list = list(key)
    idx = len(key_list) - 1
    while idx >= 0:
        char = key_list[idx]
        char_idx = charset.index(char)
        char_idx += 1
        if char_idx >= base:
            key_list[idx] = charset[0]
            idx -= 1
        else:
            key_list[idx] = charset[char_idx]
            break
    return ''.join(key_list)

# Função para gerar a chave inicial de cada grupo
def get_initial_keys(start_key, num_keys_per_group, num_groups):
    start_key_suffix = start_key[10:]  # Pegando os 6 caracteres finais da chave
    start_number = 0

    # Convertendo a chave inicial (Security00aaaaaa) para um número base 62
    for i, char in enumerate(start_key_suffix):
        start_number = start_number * 62 + charset.index(char)

    initial_keys = []
    for group in range(num_groups):
        # Calculando o número da chave inicial para o grupo
        key_number = start_number + group * num_keys_per_group
        new_suffix = []
        # Convertendo o número de volta para uma chave no formato base62
        for _ in range(6):
            new_suffix.insert(0, charset[key_number % 62])
            key_number //= 62
        initial_key = start_key[:10] + ''.join(new_suffix)
        initial_keys.append(initial_key)

    return initial_keys

# Divisões solicitadas
total_chaves = 62**6  # 62^6 chaves possíveis
divisoes = [
    (8, total_chaves // 8),
    (10, total_chaves // 10),
    (12, total_chaves // 12),
    (15, total_chaves // 15)
]

start_key = "Security00aaaaaa"  # Chave inicial com "Security00"

# Calculando as chaves iniciais para cada divisão
for grupos, chaves_por_grupo in divisoes:
    print(f"Dividido em {grupos} grupos, com {chaves_por_grupo} chaves por grupo:")
    initial_keys = get_initial_keys(start_key, chaves_por_grupo, grupos)
    for i, key in enumerate(initial_keys):
        print(f"Grupo {i+1}: {key}")
    print()
