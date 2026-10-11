#include <iostream>
#include "CliInterface.h"
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
        
        CryptoService cryptoService;

        CliInterface app(db, cryptoService);
        app.run();
    } catch (const exception& e) {
        cerr << "Erro Crítico: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}