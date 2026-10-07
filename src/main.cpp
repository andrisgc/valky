/**
 * @file main.cpp
 * @brief Teste de inicialização e Derivação de Chave (KDF) da arquitetura do Valky.
 * @details Este módulo simula o passo inicial da arquitetura Zero-Knowledge,
 *          transformando a senha em uma chave criptográfica de alta entropia. 
 */
#include <iostream>
#include <vector>
#include <sodium.h>
#include "SecureString.h"
#include "CryptoService.h"

using namespace std;

int main () {
    
    try {
        CryptoService cryptoService;

        SecureString masterPassword("senha123");

        vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
        randombytes_buf(salt.data(), salt.size());

        std::cout << "[1] Derivando a chave...\n";
        if (!cryptoService.deriveKey(masterPassword, salt.data())) {
            cerr << "Falha ao derivar a chave.\n";
            return 1;
        }
        cout << "Chave mestra derivada com sucesso.\n\n";

        SecureString plaintextData("senhadobanco123");

        // Criptografando um dado.
        vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);

        cout << "[2] Criptografando senha...\n";
        vector<unsigned char> cipherText = cryptoService.encrypt(plaintextData, nonce.data());
        cout << "Dado criptografado.\n\n";

        // Descriptografando um dado.
        cout << "[3] Descriptografando o dado...\n";
        SecureString retriviedText = cryptoService.decrypt(cipherText, nonce.data());

        cout << "Dado descriptografado com sucesso.\n";
        cout << "Senha: " << retriviedText.c_str() << "\n\n";
    } catch (const exception& e) {
        cerr << "Erro Crítico: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}