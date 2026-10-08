#include "DatabaseManager.h"
#include <iostream>
#include <stdexcept>

using namespace std;

DatabaseManager::DatabaseManager(const string& path) : db(nullptr), dbPath(path) {
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        string error = sqlite3_errmsg(db);
        sqlite3_close(db);
        throw runtime_error("Erro ao abrir o banco SQLite: " + error);
    }
}

DatabaseManager::~DatabaseManager() {
    if (db) 
        sqlite3_close(db);
}


bool DatabaseManager::executeQuery(const string& query) {
    char* error = nullptr;
    if (sqlite3_exec(db, query.c_str(), nullptr, nullptr, &error) != SQLITE_OK) {
        cerr << "Erro no SQL: " << error << "\n";
        sqlite3_free(error);
        return false;
    }
    return true;
}

bool DatabaseManager::initializeDatabase() {
    executeQuery("PRAGMA foreign_keys = ON;");

    string createConfigTable = R"(
        CREATE TABLE IF NOT EXISTS vaults (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            salt BLOB NOT NULL
        );
    )";

    string createCredsTable = R"(
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vault_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            cipherText BLOB NOT NULL,
            nonce BLOB NOT NULL,
            FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
        );
    )";

    return executeQuery(createConfigTable) && executeQuery(createCredsTable);
}

bool DatabaseManager::createVault(const string& name, const vector<unsigned char>& salt) {
    const char* sql = "INSERT INTO vaults (name, salt) VALUES (?, ?)";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, salt.data(), salt.size(), SQLITE_STATIC);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return success;
}

vector<VaultRecord> DatabaseManager::getAllVaults() {
    vector<VaultRecord> vaults;
    const char* sql = "SELECT id, name, salt FROM vaults";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            VaultRecord vault;
            vault.id = sqlite3_column_int(stmt, 0);
            vault.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

            const unsigned char* saltBlob = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 2));
            int saltSize = sqlite3_column_bytes(stmt, 2);
            if (saltBlob && saltSize) vault.salt.assign(saltBlob, saltBlob + saltSize);

            vaults.push_back(vault);
        }
        sqlite3_finalize(stmt);
    }

    return vaults;
}

bool DatabaseManager::insertCredential(int vaultId,
                                       const string& service,
                                       const string& username,
                                       const vector<unsigned char>& cipherText,
                                       const vector<unsigned char>& nonce) {
    
    const char* sql = "INSERT INTO credentials (vault_id, service, username, cipherText, nonce) VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int(stmt, 1, vaultId);
    sqlite3_bind_text(stmt, 2, service.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, cipherText.data(), cipherText.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, nonce.data(), nonce.size(), SQLITE_STATIC);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return success;
}

vector<CredentialRecord> DatabaseManager::getCredentialsByVault(int vaultId) {
    vector<CredentialRecord> credentials;
    const char* sql = "SELECT id, vault_id, service, username, cipherText, nonce FROM credentials WHERE vault_id = ?";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, vaultId);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            CredentialRecord credential;
            credential.id = sqlite3_column_int(stmt, 0);
            credential.vaultId = sqlite3_column_int(stmt, 1);
            credential.service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            credential.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

            const unsigned char* cipherTextBlob = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 4));
            int cipherTextSize = sqlite3_column_bytes(stmt, 4);
            if (cipherTextBlob && cipherTextSize > 0) credential.cipherText.assign(cipherTextBlob, cipherTextBlob + cipherTextSize);

            const unsigned char* nonceBlob = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 5));
            int nonceSize = sqlite3_column_bytes(stmt, 5);
            if (nonceBlob && nonceSize > 0) credential.nonce.assign(nonceBlob, nonceBlob + nonceSize);

            credentials.push_back(credential);
        }
        sqlite3_finalize(stmt);
    }

    return credentials;
}

