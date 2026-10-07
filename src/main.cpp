#include <iostream>
#include <sodium.h>

using namespace std;

int main () {
    cout << "Iniciando o Valky...\n";

    if (sodium_init() < 0) {
        cerr << "Erro: O Sodium não pode ser inicializado.";
        return 1;
    }

    cout << "Libsodium inicializado com sucesso. O ambiente está pronto.\n";

    return 0;
}