#!/bin/bash

# Instalar dependências (OpenSSL)
# sudo apt-get install libssl-dev

# Compilar o código C++
g++ -o decryptor decryptor.cpp -lssl -lcrypto

# Executar o programa
./decryptor
