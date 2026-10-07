/**
 * @file CryptoService.cpp
 * @brief Implementação do motor criptográfico responsável pela derivação de chaves e encriptação.
 */
#include "CryptoService.h"
#include <stdexcept>
#include <iostream>

using namespace std;

CryptoService::CryptoService() {
        if (sodium_init() < 0)
            throw runtime_error("Erro crítico: Falha ao inicializar Libsodium.");

    masterKey.resize(crypto_secretbox_KEYBYTES);
}

CryptoService::~CryptoService() {
    if (!masterKey.empty())
        sodium_memzero(masterKey.data(), masterKey.size());
}

bool CryptoService::deriveKey(const SecureString& masterPassword, const unsigned char* salt) {
    if (crypto_pwhash(
            masterKey.data(), masterKey.size(),
            masterPassword.c_str(), masterPassword.size(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return false;
    }
    return true;
}

vector<unsigned char> CryptoService::encrypt(const SecureString& plaintextData, unsigned char* outNonce) {
    randombytes_buf(outNonce, crypto_secretbox_NONCEBYTES);

    vector<unsigned char> cipherText(plaintextData.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(
            cipherText.data(),
            reinterpret_cast<const unsigned char*>(plaintextData.c_str()),
            plaintextData.size(),
            outNonce,
            masterKey.data()
    );

    return cipherText;
}

SecureString CryptoService::decrypt(const vector<unsigned char>& cipherText, const unsigned char* nonce) {
    if (cipherText.size() < crypto_secretbox_MACBYTES)
        throw runtime_error("Ciphertext corrompido ou pequeno demais.");

    vector<unsigned char> decrypted(cipherText.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(
            decrypted.data(), 
            cipherText.data(), cipherText.size(),
            nonce,
            masterKey.data()) != 0) {
        throw runtime_error("Falha na integridadade: Cofre adulterado ou chave incorreta!");
    }

    string retriviedText(decrypted.begin(), decrypted.end());

    sodium_memzero(decrypted.data(), decrypted.size());

    return SecureString(retriviedText);
}