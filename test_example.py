from Crypto.Cipher import AES
import binascii
import string

digitos = 'qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPLKJHGFDSAZXCVBNM0123456789'

# Função para salvar o texto no arquivo de saída
def save_text(decrypted_text, key):
    with open('saida_test.txt', 'a') as saida:
        saida.write('Chave: ')
        saida.write(key)
        saida.write('\n')
        saida.write(decrypted_text)
        saida.write('\n-------------------------------------------------------------------------------\n')

def is_text_legible(text, encoding):
    """
    Função que verifica se mais de 50% do texto é legível no encoding especificado.
    """
    try:
        decoded_text = text.decode(encoding)
        # Conta o número de caracteres legíveis (letras, dígitos, espaços e pontuações básicas)
        legible_chars = sum(c.isalnum() or c.isspace() or c in string.punctuation for c in decoded_text)
        # Verifica se mais de 50% do texto é legível
        return (legible_chars / len(decoded_text)) > 0.5
    except (UnicodeDecodeError, TypeError):
        return False

def is_text_mostly_legible(text, decoder):
    """
    Função que verifica se mais de 50% do texto é legível tanto em utf-8 como em latin-1.
    """
    return is_text_legible(text, decoder)

# Função para decifrar texto com AES-ECB
def decrypt_aes_ecb(hex_data, key):
    # Converte o texto hexadecimal para bytes
    encrypted_bytes = binascii.unhexlify(hex_data)
    # Cria uma instância do AES com a chave e o modo ECB
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    # Decifra os bytes
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    # Remove padding e converte os bytes decifrados para texto
    decrypted_text = ""
    try:
        decrypted_text = decrypted_bytes.decode('utf-8').strip()
        if is_text_mostly_legible(decrypted_text.encode('utf-8'), 'utf-8'):
            return decrypted_text
        decrypted_text = decrypted_bytes.decode('latin-1').strip()
        if is_text_mostly_legible(decrypted_text.encode('latin-1'), 'latin-1'):
            return decrypted_text
    except UnicodeDecodeError:
        decrypted_text = ""
    return decrypted_text

# Texto hexadecimal fornecido
hex_data = (
    'ffe19bb7d65685c50e178ba107e8e300'
    '23479b1265e98740a7181303d2db056a'
    '88c61d6d70aea3ea6334c1d670f10bf6'
    '53330d49bf4159bf641d23286f9b360e'
    '5315c1a73d791d14d561e45df7d046b0'
    '0725f014759fab1f4a278ed0bb1274b9'
    '736d1aa2a5d283b207f31712e95db711'
    '7d3c1830575eae2d7c1f54174df6bbce'
    '0a16957b8a8eed07c6eb5081e075ff7b'
    '6077993ebddb7e6c8b396d626badb7f9'
    'e5ed83c6cf19bf893c3d2eb9c3930a46'
    '0581baf03277dd0eeb44928f791b8c56'
    '4c79af82d758a211832edf34c8d44f1b'
    'cfb8c389e08486a4330fc382d2b48394'
    '194ebc3ff66e181570239d1585da57ed'
    '2afe8ef65086cd97ea793766e7f6545f'
    '28dc6d649c1585228151dd5592ac5bc8'
    '1cb03cf5a3550e0ed1f9f697e769e96a'
    '63a725a17b4c2b1af84223aecfe841c2'
    '929f724dccf9d28efc2528e3d64bc6b6'
    'eb64d50f9ddb808e25ecc7ed04608102'
    'd4b2f826c60ac04a0fbac474d3dedbce'
    '4b17bc22170fe76ea66fec0d7cb1e8b1'
    '00eb539c13951394f82210a52b35c676'
    '557f16232912ccf3001b2e78ea592e11'
    'f047834f51fcd124dacbf9613bfd8657'
    'b0f51caaf2cb5410021a33fe33d9483e'
    'c6d5a5c954f0b79bb3ef91b78547e8dd'
    '77d80703935640be76b6c49aae73a9a5'
    '20aabb19d9b6f48ecc5a40d3836ac9d6'
    '700e70d0edd267d7dcd08a97722c1e6a'
    '04c27661a3bc4a6822a35828cb759430'
    '606079914f8aeb2155087490b0519e3f'
    '24c24dcb7ea82046b50a0421ffb59262'
    'e72b73bcc66b1ebf0a9bc7c89a9f4b1a'
    'ba7e3f9ce0b57ff4fd040ec3ea4ec5c8'
    '272afdac96f4265c3918727d2b40f055'
    '906c49d1eb6ee6c441f968e28824490a'
    '841108c00a74e919fad07af9eda67393'
    'c48ef81077688f4e22f267df4aed473d'
    '899dd36b8b2126edad7253291d7a69c4'
    '235ca66aed459e92ed787bb9fe5c6927'
    '00c933c39ea71c89c03b5c2cbc07e65f'
    'acd110e78acc9ad0f7047faa0d4ac514'
    'bfea773b2f4b7cd7bc362dfa88bd1075'
    'c23d5fd558cb1f8f68c1a367bb2d0d01'
    '61972b50a59a2ba7b5bfe250da6d2380'
    '749566b441ab5f763f279ae3b7041404'
    '6361fc71aea82cc91d2c1141fe760c20'
    '4d8a30fa2d3623bf16ede954c5a220be'
    '40fcb9cd1a218b44e532ef5f4129ebbe'
    '3221cb1ee981598c51db16f4324b9fde'
    '9e528d2e2841c7f6bbbf0866f3c778ce'
    '1ebccec045d11a9716d2313546259d1c'
    '9221af59e615d79a20203d349d621835'
    'c4856e0ad9e35b39f4677d21ec791528'
    '9df5beb98564ea493f793102120a1503'
    'b32053c8444f193eb91232acac19af32'
    'ac13bee41cb0a31fd786729b381d871f'
    'eb6041554ef0892b3dcaa4f264b52c61'
    '2fe1941a5e5bf536aef7c83d0be59c41'
    'c6208d386e035086dfcdc564997e0220'
    '5440fdd75d17ac782e600ff265882c5a'
    '5934632b1f1de464a06f096ca385202c'
    '88882fa4de39662542ca9fad477389cf'
    '947c046efb66f33fe5cfdc7eea5f1ece'
    'fceec04ee26f7985271b976707dad28e'
    '2df4052ec6749a24121e19a698bdad24'
    'e6c74ddc472935a145581b09a81bd5ff'
    '5f6de81bd83b7fb7853be9629cbd74cc'
    'aa0675a60923d19746713e1dce858c53'
    'c1f801ed3134285d1087ba0a6d507c59'
    '98f3184d6c60044697d629af01f78eeb'
    '97d877e3ce09821f96fa58d0da947d0d'
    '3212ba6e86eb92874438e765b8fb71db'
    'a54d3007228a67d4053a4c3c3aa47ef0'
    '7451ace69682aa71be12bbc222a56cdd'
    '77c2b5e2bf2ff2351e5d526782618578'
    'b84604eb2d6457a32a485a8811d69187'
    '92e568cbf6002727c2fef3ec550f2f9f'
    '36c693105aa8df3a062cbb0424962fe1'
    '513ac9e6441b6f85a5549439564fa8af'
    '70e992678c0174da7773fc8e4212a7dd'
    'ca0aaf9289065dc5240716ba3c65d178'
    '6f9673fd7540939d7982fc2fdef9bb97'
    '0123c915910dfdd8524664dfad3ce890'
    '467ca4c4aec273bb66c10693828f8727'
    '9cb5a5e55d2fce34bce5dfb1eb4d1be1'
    '4beba8c5dc03787c98839aad1dd16167'
    '46b44cde68de713df765ac170b8fdb78'
    '06a95afdfed11395bccf4de69b6e6c10'
    '47b9b5972deec291fd26b59432c767c8'
    'addbfc70dabcbd203cccd4f01d9169a4'
    '4a3a64faf0e605d11d536e6955d664ef'
    '15e80543e6736a7acc09eec3085d1bec'
    'c40320a105ec347248b9434866324aab'
    'cd7c861e49ae835c676241e85ef4c4d0'
    '650f2f3a4c37bc76eb199e1584f468a5'
    '3c86d7ed1b67173ab8d9b8dffcd89229'
    '94342a1c506632a1c78e4abdf6e7fded'
    'f0b4ba1fa342d7812ff06159a8ab23f2'
    'f9f67f454e40e0499047c18a1dabda80'
)

# Chave inicial
key_weak = 'SecurityAES'  # Chave inicial no formato correto

flag_end = False
while (not flag_end):
    for i in digitos:
        for j in digitos:
            for k in digitos:
                for l in digitos:
                    for m in digitos:
                        key = key_weak + i + j + k + l + m
                        # Decifra o texto
                        try:
                            decrypted_text = decrypt_aes_ecb(hex_data, key)
                            if len(decrypted_text) > 0:
                                print('Chave boa.')
                                # Salva o texto num arquivo
                                save_text(decrypted_text, key)
                        except ValueError as e:
                            print(f"Erro: {e} com a chave: {key}")
                            continue
    flag_end = True
    
print('Tentativas finalizadas. Verificar arquivo de saída!')
