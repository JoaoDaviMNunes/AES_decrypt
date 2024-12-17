/*
Instituto de Informática
João Davi Martins Nunes
*/

#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <openssl/evp.h>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <cctype>
#include <stdexcept>

using namespace std;

// Constantes
constexpr int MAX_READABLE_BYTES = 32; // Número máximo de bytes legíveis a verificar
string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Mutex para proteger saídas e outros recursos compartilhados
mutex outputMutex;
atomic<bool> found(false); // Flag para indicar se a chave foi encontrada

// Função para validar se uma string contém apenas caracteres hexadecimais válidos
bool isValidHex(const string& hex) {
    for (char c : hex) {
        if (!isxdigit(c)) {
            return false;
        }
    }
    return true;
}

// Função para converter hex para bytes
vector<unsigned char> hexToBytes(const string& hex) {
    if (hex.length() % 2 != 0) {
        throw invalid_argument("O comprimento da string hexadecimal deve ser par.");
    }

    if (!isValidHex(hex)) {
        throw invalid_argument("A string contém caracteres não-hexadecimais.");
    }

    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        try {
            string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        } catch (const invalid_argument& e) {
            throw invalid_argument("Erro ao converter hexadecimal: " + hex.substr(i, 2));
        }
    }
    return bytes;
}

// Função que verifica se os bytes estão em ASCII legíveis
bool isReadableASCII(const vector<unsigned char>& bytes) {
    if (bytes.size() < MAX_READABLE_BYTES) return false;

    for (int i = 0; i < MAX_READABLE_BYTES; ++i) {
        if (!isprint(bytes[i]) && bytes[i] != '\n' && bytes[i] != '\r') {
            return false;
        }
    }
    return true;
}

// Função recursiva para gerar combinações de chaves e testar
void bruteForce(const vector<unsigned char>& cipherBytes, const string& baseKey, int depth, int maxDepth, EVP_CIPHER_CTX* ctx) {
    if (found.load()) return; // Encerrar se outra thread encontrar a chave

    if (depth == maxDepth) {
        vector<unsigned char> decryptedBytes(cipherBytes.size());

        // Reseta o contexto
        EVP_CIPHER_CTX_reset(ctx);

        // Configuração da descriptografia
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, reinterpret_cast<const unsigned char*>(baseKey.c_str()), nullptr);
        EVP_CIPHER_CTX_set_padding(ctx, 0); // Desabilita o padding

        int outlen = 0;
        if (!EVP_DecryptUpdate(ctx, decryptedBytes.data(), &outlen, cipherBytes.data(), cipherBytes.size())) {
            return; // Falha na descriptografia
        }

        if (isReadableASCII(decryptedBytes)) {
            lock_guard<mutex> lock(outputMutex);
            if (!found.exchange(true)) {
                cout << "Chave encontrada: " << baseKey << endl;
                cout << "Primeiros 32 bytes descriptografados: ";
                for (int i = 0; i < MAX_READABLE_BYTES; ++i) {
                    cout << static_cast<char>(decryptedBytes[i]);
                }
                cout << endl;
            }
        }
        return;
    }

    for (char c : charset) {
        if (found.load()) return;
        bruteForce(cipherBytes, baseKey + c, depth + 1, maxDepth, ctx);
    }
}

// Função para gerenciar threads
void threadWorker(const vector<unsigned char>& cipherBytes, const string& prefix, int maxDepth) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    bruteForce(cipherBytes, prefix, 0, maxDepth, ctx);
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // Inicializa o contexto OpenSSL
    OpenSSL_add_all_algorithms();

    // Conteúdo do arquivo .hex
    string hexContent = "ffe19bb7d65685c50e178ba107e8e30023479b1265e98740a7181303d2db056a88c61d6d70aea3ea6334c1d670f10bf653330d49bf4159bf641d23286f9b360e5315c1a73d791d14d561e45df7d046b00725f014759fab1f4a278ed0bb1274b9736d1aa2a5d283b207f31712e95db7117d3c1830575eae2d7c1f54174df6bbce0a16957b8a8eed07c6eb5081e075ff7b6077993ebddb7e6c8b396d626badb7f9e5ed83c6cf19bf893c3d2eb9c3930a460581baf03277dd0eeb44928f791b8c564c79af82d758a211832edf34c8d44f1bcfb8c389e08486a4330fc382d2b48394194ebc3ff66e181570239d1585da57ed2afe8ef65086cd97ea793766e7f6545f28dc6d649c1585228151dd5592ac5bc81cb03cf5a3550e0ed1f9f697e769e96a63a725a17b4c2b1af84223aecfe841c2929f724dccf9d28efc2528e3d64bc6b6eb64d50f9ddb808e25ecc7ed04608102d4b2f826c60ac04a0fbac474d3dedbce4b17bc22170fe76ea66fec0d7cb1e8b100eb539c13951394f82210a52b35c676557f16232912ccf3001b2e78ea592e11f047834f51fcd124dacbf9613bfd8657b0f51caaf2cb5410021a33fe33d9483ec6d5a5c954f0b79bb3ef91b78547e8dd77d80703935640be76b6c49aae73a9a520aabb19d9b6f48ecc5a40d3836ac9d6700e70d0edd267d7dcd08a97722c1e6a04c27661a3bc4a6822a35828cb759430606079914f8aeb2155087490b0519e3f24c24dcb7ea82046b50a0421ffb59262e72b73bcc66b1ebf0a9bc7c89a9f4b1aba7e3f9ce0b57ff4fd040ec3ea4ec5c8272afdac96f4265c3918727d2b40f055906c49d1eb6ee6c441f968e28824490a841108c00a74e919fad07af9eda67393c48ef81077688f4e22f267df4aed473d899dd36b8b2126edad7253291d7a69c4235ca66aed459e92ed787bb9fe5c692700c933c39ea71c89c03b5c2cbc07e65facd110e78acc9ad0f7047faa0d4ac514bfea773b2f4b7cd7bc362dfa88bd1075c23d5fd558cb1f8f68c1a367bb2d0d0161972b50a59a2ba7b5bfe250da6d2380749566b441ab5f763f279ae3b70414046361fc71aea82cc91d2c1141fe760c204d8a30fa2d3623bf16ede954c5a220be40fcb9cd1a218b44e532ef5f4129ebbe3221cb1ee981598c51db16f4324b9fde9e528d2e2841c7f6bbbf0866f3c778ce1ebccec045d11a9716d2313546259d1c9221af59e615d79a20203d349d621835c4856e0ad9e35b39f4677d21ec7915289df5beb98564ea493f793102120a1503b32053c8444f193eb91232acac19af32ac13bee41cb0a31fd786729b381d871feb6041554ef0892b3dcaa4f264b52c612fe1941a5e5bf536aef7c83d0be59c41c6208d386e035086dfcdc564997e02205440fdd75d17ac782e600ff265882c5a5934632b1f1de464a06f096ca385202c88882fa4de39662542ca9fad477389cf947c046efb66f33fe5cfdc7eea5f1ecefceec04ee26f7985271b976707dad28e2df4052ec6749a24121e19a698bdad24e6c74ddc472935a145581b09a81bd5ff5f6de81bd83b7fb7853be9629cbd74ccaa0675a60923d19746713e1dce858c53c1f801ed3134285d1087ba0a6d507c5998f3184d6c60044697d629af01f78eeb97d877e3ce09821f96fa58d0da947d0d3212ba6e86eb92874438e765b8fb71dba54d3007228a67d4053a4c3c3aa47ef07451ace69682aa71be12bbc222a56cdd77c2b5e2bf2ff2351e5d526782618578b84604eb2d6457a32a485a8811d6918792e568cbf6002727c2fef3ec550f2f9f36c693105aa8df3a062cbb0424962fe1513ac9e6441b6f85a5549439564fa8af70e992678c0174da7773fc8e4212a7ddca0aaf9289065dc5240716ba3c65d1786f9673fd7540939d7982fc2fdef9bb970123c915910dfdd8524664dfad3ce890467ca4c4aec273bb66c10693828f87279cb5a5e55d2fce34bce5dfb1eb4d1be14beba8c5dc03787c98839aad1dd1616746b44cde68de713df765ac170b8fdb7806a95afdfed11395bccf4de69b6e6c1047b9b5972deec291fd26b59432c767c8addbfc70dabcbd203cccd4f01d9169a44a3a64faf0e605d11d536e6955d664ef15e80543e6736a7acc09eec3085d1becc40320a105ec347248b9434866324aabcd7c861e49ae835c676241e85ef4c4d0650f2f3a4c37bc76eb199e1584f468a53c86d7ed1b67173ab8d9b8dffcd8922994342a1c506632a1c78e4abdf6e7fdedf0b4ba1fa342d7812ff06159a8ab23f2f9f67f454e40e0499047c18a1dabda80";

    try {
        vector<unsigned char> cipherBytes = hexToBytes(hexContent);

        // Divide o trabalho entre threads
        const int numThreads = thread::hardware_concurrency();
        vector<thread> threads;

        int maxDepth = 5; // Configurar profundidade máxima da chave
        for (int i = 0; i < numThreads; ++i) {
            string prefix = charset.substr(i * charset.length() / numThreads, charset.length() / numThreads);
            threads.emplace_back(threadWorker, ref(cipherBytes), prefix, maxDepth);
        }

        for (auto& t : threads) {
            t.join();
        }

        if (!found) {
            cout << "Nenhuma chave válida encontrada." << endl;
        }
    } catch (const exception& e) {
        cerr << "Erro: " << e.what() << endl;
    }

    return 0;
}
