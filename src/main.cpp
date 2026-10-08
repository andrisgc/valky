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

        vector<VaultRecord> vaults = db.getAllVaults();
        if (vaults.empty()) {
            cout << "[INFO] Nenhum vault encontrado. Criando vault principal...\n";
            vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
            randombytes_buf(salt.data(), salt.size());

            if (!db.createVault("Vault 1", salt)) {
                cerr << "Falha ao criar vault.\n";
                return 1;
            }

            vaults = db.getAllVaults();
        }

        VaultRecord myVault = vaults[0];
        cout << "[OK] Vault selecionado: " << myVault.name << "(ID: " << myVault.id << ")\n";

        SecureString masterPassword("senha123");
        cout << "[OK] Derivando a chave mestra...\n";
        if (!cryptoService.deriveKey(masterPassword, myVault.salt.data())) {
            cerr << "Falha ao derivar a master key.\n";
            return 1;
        }

        // Mock
        string serviceName = "Gmail";
        string userName = "usuario";
        SecureString plaintextData("s3cr3t");

        vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
        vector<unsigned char> cipherText = cryptoService.encrypt(plaintextData, nonce.data());

        if (db.insertCredential(myVault.id, serviceName, userName, cipherText, nonce))
            cout << "[OK] Credencial salva no vault " << myVault.name << ".\n";

        cout << "Lendo senhas do vault...\n";
        vector<CredentialRecord> credentials = db.getCredentialsByVault(myVault.id);

        for (const CredentialRecord& credential : credentials) {
            cout << "-> Descriptografando: " << credential.service << " (" << credential.username << ")\n";
            try {
                SecureString decrypted = cryptoService.decrypt(credential.cipherText, credential.nonce.data());
                cout << "    [SUCESSO] Senha recuperada: " << decrypted.c_str() << "\n";
            } catch (const exception& e) {
                cerr << "    [FALHA] Integridade comprometida ou chave incorreta: " << e.what() << "\n";
            }
        }

    } catch (const exception& e) {
        cerr << "Erro Crítico: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}