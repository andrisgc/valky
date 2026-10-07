#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>

using namespace std;

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

    vector<unsigned char> getSalt();

    bool storeSalt(const vector<unsigned char>& salt);

    bool insertCredential(const string& service,
                          const string& username,
                          const vector<unsigned char>& cipherText,
                          const vector<unsigned char>& nonce);

};