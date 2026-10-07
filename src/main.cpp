#include <iostream>
#include <vector>
#include <sodium.h>
#include "SecureString.h"
#include "CryptoService.h"
#include "DatabaseManager.h"

using namespace std;

int main () {
    
    try {
        DatabaseManager db("valky_vault.db");
        if (!db.initializeDatabase()) {
            cerr << "Falha ao inicializar as tabelas do DB.";
            return 1;
        }
        cout << "[OK] Banco de dados inicializado.\n";

        // Inicializa motor criptográfico.
        CryptoService cryptoService;

        vector<unsigned char> salt = db.getSalt();
        if (salt.empty()) {
            cout << "[INFO] Primeiro uso detectado. Gerando novo Salt...\n";
            salt.resize(crypto_pwhash_SALTBYTES);
            randombytes_buf(salt.data(), salt.size());

            if (!db.storeSalt(salt)) {
                cerr << "Falha ao salvar o Salt no DB.\n";
                return 1;
            }
        }

        SecureString masterPassword("senha123");
        
        cout << "[OK] Derivando a chave mestra...\n";
        if (!cryptoService.deriveKey(masterPassword, salt.data())) {
            cerr << "Falha ao derivar a master key.\n";
            return 1;
        }

        // Mock
        string serviceName = "GitHub";
        string userName = "usuario";
        SecureString plaintextData("s3cr3t");
        vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);

        vector<unsigned char> cipherText = cryptoService.encrypt(plaintextData, nonce.data());
        cout << "[OK] Senha do " << serviceName << " criptografada com sucesso.\n";

        if (db.insertCredential(serviceName, userName, cipherText, nonce)) {
            cout << "[OK] Credencial salva no banco de dados 'valky_vault.db'.\n";
        } else {
            cerr << "Falha ao inserir credencial no banco.\n";
        }

    } catch (const exception& e) {
        cerr << "Erro Crítico: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}