/**
 * @file SecureString.h
 * @brief Classe para gerenciamento seguro de strings na memória RAM.
 */
#pragma once

#include <string>
#include <vector>
#include <sodium.h>

using namespace std;

class SecureString {
private:
    vector<char> data;

public:
    explicit SecureString(const string& plaintext);

    ~SecureString();

    const char* c_str() const;
    size_t size() const;
};