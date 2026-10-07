/**
 * @file SecureString.cpp
 * @brief Implementação da classe SecureString com limpeza de memória (RAII).
 */
#include "SecureString.h"

using namespace std;

SecureString::SecureString(const string& plaintext) {
    data.assign(plaintext.begin(), plaintext.end());
    data.push_back('\0');
}

SecureString::~SecureString() {
    if (!data.empty())
        sodium_memzero(data.data(), data.size()); // Preenche a RAM com zeros.
}

const char* SecureString::c_str() const {
    return data.data();
}

size_t SecureString::size() const {
    return data.size() > 0 ? data.size() - 1 : 0;
}