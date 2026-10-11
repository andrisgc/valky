#pragma once
#include "DatabaseManager.h"
#include "CryptoService.h"

class CliInterface {
private:
    DatabaseManager& db;
    CryptoService& crypto;
    int currentVaultId;
    bool isRunning;

    void showMenu();
    void createVault();
    void loginVault();

    void showVaultMenu();
    void addCredential();
    void listCredentials();

    void clearScreen();
    void pause();

public:
    CliInterface(DatabaseManager& databaseManager, CryptoService& cryptoService);

    void run();
};