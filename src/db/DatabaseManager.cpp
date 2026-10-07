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
    string createConfigTable = R"(
        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL
        );
    )";

    string createCredsTable = R"(
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            cipherText BLOB NOT NULL,
            nonce BLOB NOT NULL
        );    
    )";

    return executeQuery(createConfigTable) && executeQuery(createCredsTable);
}

bool DatabaseManager::storeSalt(const vector<unsigned char>& salt) {
    const char* sql = "INSERT OR REPLACE INTO config (id, salt) VALUES (1, ?)";
    sqlite3_stmt* stmt;

    // Prepara o statement.
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    // Injeta Salt no DB de forma segura.
    sqlite3_bind_blob(stmt, 1, salt.data(), salt.size(), SQLITE_STATIC);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt); // Destrói statement.

    return success;
}

vector<unsigned char> DatabaseManager::getSalt() {
    const char* sql = "SELECT salt FROM config WHERE id = 1";
    sqlite3_stmt* stmt;
    vector<unsigned char> salt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* blob = static_cast<const unsigned char*>(sqlite3_column_blob(stmt,0));
            int size = sqlite3_column_bytes(stmt, 0);

            if (blob && size > 0) {
                salt.assign(blob, blob + size);
            }
        }
        sqlite3_finalize(stmt);
    }

    return salt;
}

bool DatabaseManager::insertCredential(const string& service,
                                       const string& username,
                                       const vector<unsigned char>& cipherText,
                                       const vector<unsigned char>& nonce) {
    
    const char* sql = "INSERT INTO credentials (service, username, cipherText, nonce) VALUES (?, ?, ?, ?)";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, service.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, cipherText.data(), cipherText.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, nonce.data(), nonce.size(), SQLITE_STATIC);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return success;
}