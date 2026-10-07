cmake_minimum_required(VERSION 3.10)

project(Valky)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(
	include/core
	include/crypto
	include/db
)

add_executable(valky
	src/main.cpp
	src/core/SecureString.cpp
	src/crypto/CryptoService.cpp
)

target_link_libraries(valky sodium sqlite3)
