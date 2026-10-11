#include "CliInterface.h"
#include "SecureString.h"
#include <limits>
#include <iostream>
#include <vector>
#include <string>
#include <sodium.h>

CliInterface::CliInterface(DatabaseManager& databaseManager, CryptoService& cryptoService)
    : db(databaseManager), crypto(cryptoService), currentVaultId(-1), isRunning(true) {}

void CliInterface::run() {
    while (isRunning) {
        if (currentVaultId == -1)
            showMenu();
        else
            showVaultMenu();
    }
}

void CliInterface::showMenu() {
    clearScreen();

    cout << "            _ _           " << endl;
    cout << "__   ____ _| | | ___   _  " << endl;
    cout << "\\ \\ / / _` | | |/ / | | | " << endl;
    cout << " \\ V / (_| | |   <| |_| | " << endl;
    cout << "  \\_/ \\__,_|_|_|\\_\\\\__, | " << endl;
    cout << "                   |___/  " << endl;

    cout << "\n--- MENU PRINCIPAL ---\n";
    cout << "1. Entrar em um vault\n";
    cout << "2. Criar novo vault\n";
    cout << "3. Sair\n";
    cout << "Escolha: ";

    int choice;
    cin >> choice;

    switch (choice) {
        case 1: loginVault(); break;
        case 2: createVault(); break;
        case 3: isRunning = false; break;
        default: cout << "[ERRO] Opção inválida.\n";
    }
}

void CliInterface::createVault() {
    clearScreen();

    cout << "\n--- NEW VAULT ---\n";
    cout << "Nome do vault: ";
    string name;
    cin >> name;

    vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    if (db.createVault(name, salt))
        cout << "[SUCESSO] Vault '" << name << "' criado! Agora faça o login.\n";
    else
        cout << "[ERRO] Falha ao criar vault.\n";
}

void CliInterface::loginVault() {
    clearScreen();

    auto vaults = db.getAllVaults();
    if (vaults.empty()) {
        cout << "[INFO] Nenhum vault encontrado. Crie um primeiro.\n";
        pause();
        return;
    }

    cout << "\n--- VAULTS ---\n";
    for (const auto& v : vaults)
        cout << "ID: " << v.id << " | Nome: " << v.name << "\n";

    cout << "Digite o ID do vault: ";
    int id;
    cin >> id;

    vector<unsigned char> vaultSalt;
    string vaultName;
    for (const auto& v : vaults) {
        if (v.id == id) {
            vaultSalt = v.salt;
            vaultName = v.name;
            break;
        }
    }

    if (vaultSalt.empty()) {
        cout << "[ERRO] Vault não encontrado!\n";
        pause();
        return;
    }

    cout << "Digite a senha mestra para '" << vaultName << "': ";
    string passwordInput;
    cin >> passwordInput;
    SecureString masterPassword(passwordInput.c_str());

    passwordInput.assign(passwordInput.size(), '0');
    passwordInput.clear();

    if (crypto.deriveKey(masterPassword, vaultSalt.data())) {
        cout << "[SUCESSO] Vault destrancado.\n";
        currentVaultId = id;
    } else
        cout << "[ERRO] Falha na derivação da chave.\n";
}

void CliInterface::showVaultMenu() {
    clearScreen();

    cout << "            _ _           " << endl;
    cout << "__   ____ _| | | ___   _  " << endl;
    cout << "\\ \\ / / _` | | |/ / | | | " << endl;
    cout << " \\ V / (_| | |   <| |_| | " << endl;
    cout << "  \\_/ \\__,_|_|_|\\_\\\\__, | " << endl;
    cout << "                   |___/  " << endl;

    cout << "\n--- VAULT (ID: " << currentVaultId << ") ---\n";
    cout << "1. Adicionar senha\n";
    cout << "2. Listar senhas\n";
    cout << "3. Fechar vault (logout)\n";
    cout << "Escolha: ";

    int choice;
    cin >> choice;

    switch (choice) {
        case 1: addCredential(); break;
        case 2: listCredentials(); break;
        case 3: currentVaultId = -1; break;
        default: cout << "[ERRO] Opção inválida.\n";
    }
}

void CliInterface::addCredential() {
    clearScreen();

    cout << "\n--- NEW CREDENTIAl ---\n";
    string service, username, password;

    cout << "Serviço: ";
    cin >> service;
    cout << "Usuário: ";
    cin >> username;
    cout << "Senha secreta: ";
    cin >> password;

    SecureString secretPassword(password.c_str());
    password.assign(password.size(), '0');
    password.clear();

    vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    vector<unsigned char> cipherText = crypto.encrypt(secretPassword, nonce.data());

    if (db.insertCredential(currentVaultId, service, username, cipherText, nonce))
        cout << "[SUCESSO] Credencial trancada e salva!\n";
    else
        cout << "[ERRO] Falha ao salvar no banco de dados.\n";
}

void CliInterface::listCredentials() {
    clearScreen();

    cout << "\n--- SUAS SENHAS ---\n";
    auto creds = db.getCredentialsByVault(currentVaultId);

    if (creds.empty()) {
        cout << "Nenhuma senha salva neste vault.\n";
        pause();
        return;
    }

    for (const auto& cred : creds) {
        try {
            SecureString decrypted = crypto.decrypt(cred.cipherText, cred.nonce.data());
            cout << "[" << cred.service << "] " << cred.username << " : " << decrypted.c_str() << "\n";
        } catch (const exception& e) {
            cout << "[" << cred.service << "] " << cred.username << " : [ERRO DE DECRIPTOGRAFIA]\n";
        }
    }

    pause();
}

void CliInterface::clearScreen() {
    cout << "\033[2J\033[1;1H";
}

void CliInterface::pause() {
    cout << "\nPressione ENTER para continuar.";

    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    cin.get();
}

