#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>

using namespace std;

// Data Transfer Object (DTO).
struct VaultRecord {
    int id;
    string name;
    vector<unsigned char> salt;
};

// Data Transfer Object (DTO).
struct CredentialRecord {
    int id;
    int vaultId;
    string service;
    string username;
    vector<unsigned char> cipherText;
    vector<unsigned char> nonce;
};

class DatabaseManager {
private:
    sqlite3* db;
    string dbPath;

    // Método auxiliar interno.
    bool executeQuery(const string& query);

public:
    DatabaseManager(const string& path);

    ~DatabaseManager();

    bool initializeDatabase();

    bool createVault(const string& name, const vector<unsigned char>& salt);

    vector<VaultRecord> getAllVaults();

    bool insertCredential(int vaultId,
                          const string& service,
                          const string& username,
                          const vector<unsigned char>& cipherText,
                          const vector<unsigned char>& nonce);

    vector<CredentialRecord> getCredentialsByVault(int vaultId);

};