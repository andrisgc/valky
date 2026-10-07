/**
 * @file CryptoService.h
 * @brief Motor criptográfico responsável pela derivação de chaves e encriptação.
 */
#pragma once

#include "SecureString.h"
#include <vector>

class CryptoService {
private:
    vector<unsigned char> masterKey;

public:
    CryptoService();

    ~CryptoService();

    // Gera a masterKey.
    bool deriveKey(const SecureString& masterPassword, const unsigned char* salt);

    // Retorna cipherText.
    vector<unsigned char> encrypt(const SecureString& plaintextData, unsigned char* outNonce);

    // Retorna plaintext em SecureString.
    SecureString decrypt(const vector<unsigned char>& cipherText, const unsigned char* nonce);

};