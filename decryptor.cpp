#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;

// Função para verificar se o texto pode ser decodificado como ASCII
bool is_ascii_readable(const string& text) {
    for (unsigned char c : text) {
        if (c < 32 || c > 126) { // Considera caracteres não ASCII visíveis
            return false;
        }
    }
    return true;
}

// Função para descriptografar o texto cifrado com a chave fornecida usando o modo ECB do AES
string decrypt_with_key(const string& key, const vector<unsigned char>& ciphertext) {
    AES_KEY decrypt_key;
    AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &decrypt_key);

    vector<unsigned char> decrypted(ciphertext.size());
    AES_ecb_encrypt(ciphertext.data(), decrypted.data(), &decrypt_key, AES_DECRYPT);

    return string(decrypted.begin(), decrypted.end());
}

// Gera a próxima chave com base em um sufixo dinâmico
string next_key(const string& suffix) {
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t base = charset.size();
    long long number = 0;

    // Converte o sufixo em um número usando a base 62
    for (char c : suffix) {
        number = number * base + charset.find(c);
    }

    // Incrementa o número
    number++;

    // Converte de volta para a string de sufixo
    string new_suffix;
    while (number > 0) {
        new_suffix = charset[number % base] + new_suffix;
        number /= base;
    }

    // Garante que o novo sufixo tenha 6 caracteres (preenche com 'a' se necessário)
    new_suffix = string(6 - new_suffix.length(), 'a') + new_suffix;

    return new_suffix;
}

// Testa uma chave e verifica se o texto descriptografado contém palavras-chave
bool test_key(const string& prefix, string& suffix, const vector<unsigned char>& ciphertext, vector<pair<string, string>>& found_results) {
    string key = prefix + suffix;

    try {
        string plaintext = decrypt_with_key(key, ciphertext);

        if (is_ascii_readable(plaintext)) {
            if (plaintext.find("codigo") != string::npos ||
                plaintext.find("Codigo") != string::npos ||
                plaintext.find("secreto") != string::npos ||
                plaintext.find("parabens") != string::npos ||
                plaintext.find("Parabens") != string::npos) {
                found_results.push_back({key, plaintext});
                cout << "Chave encontrada: " << key << endl;
                cout << "Texto Claro: " << plaintext << endl;
                return true;
            }
        }
    }
    catch (...) {
        // Ignora exceções
    }
    return false;
}

// Função para processar a busca da chave
void busca_chave(const vector<unsigned char>& ciphertext, vector<pair<string, string>>& found_results) {
    string prefix = "Security00";
    vector<string> groups = {
        "aaaaaa", "hUFaaa", "pFaaaa", "xpFaaa", "Faaaaa", "MUFaaa", "UFaaaa", "2pFaaa"
    };

    clock_t start_time = clock();
    int tested_keys = 0;
    bool flag_chave = false;

    while (!flag_chave) {
        for (size_t i = 0; i < groups.size(); ++i) {
            if (!flag_chave) {
                flag_chave = test_key(prefix, groups[i], ciphertext, found_results);
                groups[i] = next_key(groups[i]);
                tested_keys++;
            }
        }

        // Exibe progresso a cada 50 milhões de chaves testadas
        if (tested_keys % 50000000 < groups.size()) {
            double elapsed = double(clock() - start_time) / CLOCKS_PER_SEC;
            cout << "Chaves testadas: " << tested_keys << ", Tempo decorrido: " << elapsed << "s" << endl;
        }
    }

    double elapsed = double(clock() - start_time) / CLOCKS_PER_SEC;
    cout << "Concluído. Total de chaves testadas: " << tested_keys << ", Tempo decorrido: " << elapsed << "s" << endl;
}

// Função principal
void main_program(const string& input_file, const string& output_file) {
    // Leitura do arquivo de entrada
    ifstream infile(input_file);
    string ciphertext_hex;
    infile >> ciphertext_hex;

    vector<unsigned char> ciphertext(ciphertext_hex.length() / 2);
    for (size_t i = 0; i < ciphertext_hex.length(); i += 2) {
        ciphertext[i / 2] = stoi(ciphertext_hex.substr(i, 2), nullptr, 16);
    }

    vector<pair<string, string>> found_results;

    cout << "Iniciando a descriptografia..." << endl;

    busca_chave(ciphertext, found_results);

    // Salvando os resultados no arquivo de saída
    ofstream outfile(output_file);
    for (const auto& result : found_results) {
        outfile << "Chave: " << result.first << "\nTexto claro: " << result.second << "\n\n";
    }

    cout << "Descriptografia concluída. Resultados salvos." << endl;
}

int main() {
    string input_file = "arquivo-weak-4.in-full.hex";  // Substitua pelo caminho do arquivo de entrada
    string output_file = "saida_weak.txt";  // Substitua pelo caminho do arquivo de saída

    main_program(input_file, output_file);
    return 0;
}
