<div align="center">
  <img src="/docs/assets/c3/png/valky-c3-lockup-white-blue-2000.png" alt="Valky Password Manager Logo" width="800" />

  <h1>Valky Password Manager</h1>

  <p>
    Um gerenciador de senhas local, ultrasseguro e construído em C++ moderno.
  </p>

  <!-- Badges -->
  <img src="https://img.shields.io/badge/C++-17-blue.svg" alt="C++17" />
  <img src="https://img.shields.io/badge/Crypto-Libsodium-success.svg" alt="Libsodium" />
  <img src="https://img.shields.io/badge/DB-SQLite3-lightgrey.svg" alt="SQLite3" />
</div>

<br />

## 🛡️ Sobre o Projeto

O Valky Password Manager é um cofre de credenciais off-line projetado com foco absoluto em segurança de memória e criptografia forte. Diferente de soluções baseadas em nuvem, o Valky mantém todos os seus dados encriptados localmente, permitindo a criação de múltiplos cofres isolados matematicamente.

## ✨ Principais Funcionalidades

* **Múltiplos Cofres (Multi-Vault):** Organização de senhas em cofres distintos (ex: Pessoal, Trabalho), cada um com seu próprio *Salt* criptográfico.
* **Isolamento de Memória:** Uso de uma classe customizada `SecureString` que limpa as senhas em texto claro da memória RAM instantaneamente após o uso, prevenindo vazamentos em dumps de memória.
* **Criptografia (Libsodium):**
  * **Derivação de Chave:** Argon2id (proteção contra ataques de força bruta).
  * **Encriptação Autenticada:** XSalsa20-Poly1305 (confidencialidade e integridade).
* **Persistência Local (SQLite):** Banco de dados relacional embutido com integridade referencial via *Foreign Keys*.

## 🛠️ Pré-requisitos

Para compilar o projeto, você precisará ter instalado no seu ambiente Linux:

* Compilador C++ (GCC ou Clang com suporte a C++17)
* CMake (>= 3.10)
* Libsodium (`libsodium-dev`)
* SQLite 3 (`libsqlite3-dev`)

**Instalação das dependências (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install build-essential cmake libsodium-dev libsqlite3-dev
```

## 🚀 Como Compilar e Rodar

O projeto utiliza o CMake para gerenciar o processo de build de forma automatizada.

```bash
# 1. Clone o repositório
git clone https://github.com/andrisgc/valky
cd valky

# 2. Crie a pasta de build
mkdir build && cd build

# 3. Gere os arquivos de compilação
cmake ..

# 4. Compile o projeto
make

# 5. Execute o binário gerado
./valky
```

## 🚧 Próximos Passos (Roadmap)

- [x] Motor Criptográfico (Libsodium)
- [x] Gerenciamento de Memória Segura (SecureString)
- [x] Persistência Multi-Cofre (SQLite)
- [ ] Interface Interativa de Linha de Comando (CLI)
- [ ] Geração automatizada de senhas fortes
