#/bin/bash
# --------------------------------------------------------------------------
#
#  Этот скрипт пытается выполнить компиляцию библиотеки и тестовых примеров
#  для максимально большого числа компиляторов и аппаратных платформ.
#  Используйте скрипт для отладочного тестирования.
#
#  Перед запуском скрипта Вы должны установить
#   - набор компиляторов: gcc, clang, tcc, ecc (сборку ellcc компилятора clang)
#   - набор средств тестирования и запуска: valgrind, wine
#
# --------------------------------------------------------------------------
cd ..
mkdir -p libakrypt-run
cd libakrypt-run

# Сборка GCC под Linux ---------------------
mkdir -p build-gcc
cd build-gcc
cmake -DCMAKE_C_COMPILER=gcc -DLIBAKRYPT_SHARED_LIB=ON ../../libakrypt-0.x
make clean && make
valgrind ./example-intro
cd ..
echo -e "\n\n"

# Сборка Clang под Linux ---------------------
mkdir -p build-clang
cd build-clang
cmake -DCMAKE_C_COMPILER=clang -DLIBAKRYPT_SHARED_LIB=ON ../../libakrypt-0.x
make clean && make
valgrind ./example-intro
cd ..
echo -e "\n\n"

# Сборка TinyCC под Linux ---------------------
mkdir -p build-tinycc
cd build-tinycc
cmake -DCMAKE_C_COMPILER=tcc -DLIBAKRYPT_SHARED_LIB=ON ../../libakrypt-0.x
make clean && make
valgrind ./example-intro
cd ..
echo -e "\n\n"

# Сборка ellcc под Win32 -----------
mkdir -p build-mingw32
cd build-mingw32
rm -f CMakeCache.txt
cmake -DCMAKE_C_COMPILER=ecc -DCMAKE_C_FLAGS="-target x86_32-w64-mingw32" -DLIBAKRYPT_EXT=".exe" -DLIBAKRYPT_CONF="C:/Documents and Settings/All Users/Application Data/libakrypt" ../../libakrypt-0.x
make clean && make
wine ./example-intro.exe
cd ..
echo -e "\n\n"

# Сборка ellcc под Win64 -----------
mkdir -p build-mingw64
cd build-mingw64
rm -f CMakeCache.txt
cmake -DCMAKE_C_COMPILER=ecc -DCMAKE_C_FLAGS="-target x86_64-w64-mingw32" -DLIBAKRYPT_EXT=".exe" -DLIBAKRYPT_CONF="C:/Users/Default/AppData/Roaming/libakrypt" ../../libakrypt-0.x
make clean && make
wine ./example-intro.exe
cd ..
echo -e "\n\n"
