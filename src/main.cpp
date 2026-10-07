/**
 * @file main.cpp
 * @brief Teste de inicialização e Derivação de Chave (KDF) da arquitetura do Valky.
 * @details Este módulo simula o passo inicial da arquitetura Zero-Knowledge,
 *          transformando a senha em uma chave criptográfica de alta entropia. 
 */
#include <iostream>
#include <string>
#include <vector>
#include <sodium.h>

using namespace std;

/**
 * @brief Deriva uma chave criptográfica forte a partir de uma senha legível.
 * 
 * Utiliza o algoritmo Argon2id.
 * 
 * @return int Código de status (0 para sucesso, 1 para erro).
 */
int main () {
    if (sodium_init() < 0) {
        cerr << "Erro: O Sodium não pode ser inicializado.";
        return 1;
    }

    // Hash da senha mestra do vault.
    string masterPassword = "senha123";

    unsigned char salt[crypto_pwhash_SALTBYTES];
    /**
     * @note std::vector X char[]
     * masterKey: A chave derivada de 32 bytes.
     * masterKey precisa saber o próprio tamanho e de um destrutor.
     * Permite a injeção de um RAII.
     */
    vector<unsigned char> masterKey(crypto_secretbox_KEYBYTES);
    randombytes_buf(salt, sizeof salt);

    cout << "Derivando a chave...\n";
    if (crypto_pwhash(
        masterKey.data(), masterKey.size(),
        masterPassword.c_str(), masterPassword.length(),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13) != 0) {

        cerr << "Erro: Memória insuficiente para derivar a chave.\n";
        return 1;
    }

    // Criptografando um dado.
    string secretData = "senhadobanco";
    
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    vector<unsigned char> cipherText(secretData.length() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(
            cipherText.data(),
            reinterpret_cast<const unsigned char*>(secretData.c_str()), secretData.length(),
            nonce,
            masterKey.data()
    );

    // Descriptografando um dado.
    vector<unsigned char> decipherText(cipherText.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(
            decipherText.data(),
            cipherText.data(), cipherText.size(),
            nonce,
            masterKey.data()) != 0) {

        cerr << "Erro de integridade: O cofre foi adulterado ou a chave mestra está errada.\n";
        return 1;
    }

    string retriviedText(decipherText.begin(), decipherText.end());

    cout << retriviedText << "\n";

    return 0;
}