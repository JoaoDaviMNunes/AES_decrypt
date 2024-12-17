#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <chrono>
#include <cctype>
#include <algorithm>

using namespace std;

// Função para converter hex para bytes
vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Função para verificar se os bytes são legíveis em ASCII
bool isReadableASCII(const vector<unsigned char>& bytes) {
    if (bytes.size() < 16) return false;
    
    for (int i = 0; i < 16; ++i) {
        // Verifica se o caractere é imprimível (espaços, letras, números, pontuação)
        if (!isprint(bytes[i]) && bytes[i] != '\n' && bytes[i] != '\r') {
            return false;
        }
    }
    return true;
}

// Função para gerar próxima chave
bool generateNextKey(string& key) {
    // Caracteres permitidos: a-z, A-Z, 0-9
    string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    // Incrementa a chave como se fosse um número com base no charset
    for (int i = key.length() - 1; i >= 0; --i) {
        auto pos = charset.find(key[i]);
        if (pos < charset.length() - 1) {
            key[i] = charset[pos + 1];
            return true;
        } else {
            key[i] = charset[0];
        }
    }
    
    return false; // Todas as combinações foram testadas
}

int main() {
    // 1. Abrir o arquivo .hex
    ifstream hexFile("arquivo-weak-4.in-full.hex");
    if (!hexFile.is_open()) {
        cerr << "Erro ao abrir o arquivo hex" << endl;
        return 1;
    }
    
    string hexContent;
    getline(hexFile, hexContent);
    hexFile.close();
    
    // 2. Converter hex para bytes
    vector<unsigned char> cipherBytes = hexToBytes(hexContent);
    
    // 3. Gerar chave inicial
    string key = "SecurityAES00000";
    
    // Variáveis para descriptografia
    AES_KEY aesKey;
    vector<unsigned char> decryptedBytes(cipherBytes.size());
    
    // Iniciar contagem de tempo
    auto startTime = chrono::high_resolution_clock::now();
    
    // 4-6. Testar chaves por força bruta
    while (true) {
        // Preparar chave para AES
        AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &aesKey);
        
        // Descriptografar
        AES_decrypt(cipherBytes.data(), decryptedBytes.data(), &aesKey);
        
        // 6. Verificar legibilidade dos primeiros 16 bytes
        if (isReadableASCII(decryptedBytes)) {
            // 7. Calcular tempo gasto
            auto endTime = chrono::high_resolution_clock::now();
            auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime);
            
            cout << "Chave encontrada: " << key << endl;
            cout << "Tempo gasto: " << duration.count() << " ms" << endl;
            
            // Imprimir primeiros 16 bytes descriptografados
            cout << "Primeiros 16 bytes descriptografados: ";
            for (int i = 0; i < 16; ++i) {
                cout << static_cast<char>(decryptedBytes[i]);
            }
            cout << endl;
            
            //break;
        }
        
        // Gerar próxima chave
        if (!generateNextKey(key)) {
            cout << "Nenhuma chave encontrada" << endl;
            break;
        }
    }
    
    return 0;
}