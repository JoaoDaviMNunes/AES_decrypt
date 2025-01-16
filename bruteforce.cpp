#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <cctype>
#include <algorithm>
#include <condition_variable>
#include <iomanip>
#include <sstream>

// Mutex para sincronização do acesso aos resultados
std::mutex mutex_resultados;

// Estrutura para armazenar chave e texto plano
struct Resultado {
    std::string chave;
    std::string texto_plano;
};

// Função para verificar se o texto é legível em ASCII
bool texto_legivel(const std::string& texto) {
    return std::all_of(texto.begin(), texto.end(), [](unsigned char c) {
        return std::isprint(c) || std::isspace(c);
    });
}

// Função para verificar se o texto contém palavras-chave
bool contem_palavras_chave(const std::string& texto) {
    std::vector<std::string> palavras_chave = {"codigo", "Codigo", "secreto", "parabens", "Parabens"};
    for (const auto& palavra : palavras_chave) {
        if (texto.find(palavra) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Função para decifrar o texto usando a chave fornecida
std::string decifrar(const std::string& chave, const std::vector<unsigned char>& texto_cifrado) {
    AES_KEY aes_key;
    unsigned char texto_plano[texto_cifrado.size()];

    if (AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(chave.c_str()), 128, &aes_key) < 0) {
        throw std::runtime_error("Falha ao configurar a chave de decifração.");
    }

    for (size_t i = 0; i < texto_cifrado.size(); i += AES_BLOCK_SIZE) {
        AES_decrypt(&texto_cifrado[i], &texto_plano[i], &aes_key);
    }

    return std::string(reinterpret_cast<char*>(texto_plano), texto_cifrado.size());
}

// Função principal de cada thread
void processar_chaves(const std::vector<std::string>& espaco_chaves, const std::vector<unsigned char>& texto_cifrado, 
                      std::vector<Resultado>& resultados, int id_thread) {
    auto inicio = std::chrono::high_resolution_clock::now();
    size_t chaves_testadas = 0;

    for (const auto& sufixo : espaco_chaves) {
        std::string chave = "SecurityAES" + sufixo;
        try {
            std::string texto_plano = decifrar(chave, texto_cifrado);
            if (texto_legivel(texto_plano) && contem_palavras_chave(texto_plano)) {
                std::lock_guard<std::mutex> lock(mutex_resultados);
                resultados.push_back({chave, texto_plano});
            }
        } catch (...) {
            // Ignorar erros de decifração
        }

        ++chaves_testadas;
        if (chaves_testadas % 1000 == 0) {
            auto agora = std::chrono::high_resolution_clock::now();
            double tempo_decorrido = std::chrono::duration<double>(agora - inicio).count();
            std::cout << "[Thread " << id_thread << "] Chaves testadas: " << chaves_testadas
                      << ", Tempo decorrido: " << tempo_decorrido << "s\n";
        }
    }

    std::cout << "[Thread " << id_thread << "] Finalizado. Total de chaves testadas: " << chaves_testadas << "\n";
}

// Função para dividir o espaço de busca em partes
std::vector<std::vector<std::string>> dividir_espaco_busca(const std::vector<std::string>& espaco_chaves, int num_threads) {
    std::vector<std::vector<std::string>> partes(num_threads);
    size_t tamanho_parte = espaco_chaves.size() / num_threads;

    for (int i = 0; i < num_threads; ++i) {
        auto inicio = espaco_chaves.begin() + i * tamanho_parte;
        auto fim = (i == num_threads - 1) ? espaco_chaves.end() : inicio + tamanho_parte;
        partes[i] = std::vector<std::string>(inicio, fim);
    }

    return partes;
}

// Função principal
int main() {
    // Arquivos de entrada e saída
    std::string arquivo_entrada = "arquivo-weak-4.in-full.hex";
    std::string arquivo_saida = "resultados_decifrados.txt";

    // Leitura do arquivo de entrada
    std::ifstream entrada(arquivo_entrada);
    if (!entrada.is_open()) {
        std::cerr << "Erro ao abrir o arquivo de entrada." << std::endl;
        return 1;
    }

    std::string texto_hex;
    entrada >> texto_hex;
    entrada.close();

    // Conversão do texto de hexadecimal para bytes
    std::vector<unsigned char> texto_cifrado;
    for (size_t i = 0; i < texto_hex.size(); i += 2) {
        std::string byte_str = texto_hex.substr(i, 2);
        texto_cifrado.push_back(static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16)));
    }

    // Espaço de busca de chaves
    std::vector<std::string> espaco_chaves;
    std::string caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (char c1 : caracteres) {
        for (char c2 : caracteres) {
            for (char c3 : caracteres) {
                for (char c4 : caracteres) {
                    for (char c5 : caracteres) {
                        espaco_chaves.push_back(std::string{c1, c2, c3, c4, c5});
                    }
                }
            }
        }
    }

    // Configuração do paralelismo
    int num_threads = std::thread::hardware_concurrency();
    auto partes = dividir_espaco_busca(espaco_chaves, num_threads);
    std::vector<std::thread> threads;
    std::vector<Resultado> resultados;

    std::cout << "Iniciando decifração com " << num_threads << " threads." << std::endl;

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(processar_chaves, partes[i], texto_cifrado, std::ref(resultados), i);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // Salvar resultados no arquivo de saída
    std::ofstream saida(arquivo_saida);
    if (!saida.is_open()) {
        std::cerr << "Erro ao abrir o arquivo de saída." << std::endl;
        return 1;
    }

    for (const auto& resultado : resultados) {
        saida << "Chave: " << resultado.chave << "\nTexto plano: " << resultado.texto_plano << "\n\n";
    }

    std::cout << "Decifração concluída. Resultados salvos em " << arquivo_saida << "." << std::endl;
    return 0;
}
