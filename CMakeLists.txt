cmake_minimum_required(VERSION 3.10)

project(Valky)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(valky
	src/main.cpp
	src/SecureString.cpp
	src/CryptoService.cpp
)

target_link_libraries(valky sodium)
