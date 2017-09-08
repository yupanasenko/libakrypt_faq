#/bin/bash
# --------------------------------------------------------------------------
#
#  Этот скрипт пытается выполнить компиляцию библиотеки и тестовых примеров
#  для максимально большого числа компиляторов и аппаратных платформ.
#  После компиляции происходит попытка тестового запуска example-intro.
#  Используйте скрипт для отладочного тестирования.
#
#  Перед запуском скрипта Вы должны установить
#   - набор компиляторов: gcc, clang, tcc, ecc (сборку ellcc компилятора clang)
#   - набор средств тестирования и запуска: valgrind, wine, qemu
#
# --------------------------------------------------------------------------
cd ..
mkdir -p build-all
cd build-all

# Сборка GCC под Linux ---------------------
mkdir -p build-gcc
cd build-gcc
echo "Compiling by gcc (native linux)"
cmake -DCMAKE_C_COMPILER=gcc -DLIBAKRYPT_SHARED_LIB=ON ../../libakrypt-0.x
make clean && make
valgrind ./example-intro
cd ..
echo -e "\n"
read -p "press return key ..."

# Сборка Clang под Linux ---------------------
mkdir -p build-clang
cd build-clang
echo "Compiling by clang (native linux)"
cmake -DCMAKE_C_COMPILER=clang -DLIBAKRYPT_SHARED_LIB=ON ../../libakrypt-0.x
make clean && make
valgrind ./example-intro
cd ..
echo -e "\n"
read -p "press return key ..."

# Сборка TinyCC под Linux ---------------------
mkdir -p build-tinycc
cd build-tinycc
echo "Compiling by tcc (native linux)"
cmake -DCMAKE_C_COMPILER=tcc -DLIBAKRYPT_SHARED_LIB=ON ../../libakrypt-0.x
make clean && make
valgrind ./example-intro
cd ..
echo -e "\n"
read -p "press return key ..."

# Сборка ellcc под Win32 -----------
mkdir -p build-mingw32
cd build-mingw32
rm -f CMakeCache.txt
echo "Compiling by ecc (mingw32 on Windows)"
cmake -DCMAKE_C_COMPILER=ecc -DCMAKE_C_FLAGS="-target x86_32-w64-mingw32" -DLIBAKRYPT_EXT=".exe" -DLIBAKRYPT_CONF="C:/Documents and Settings/All Users/Application Data/libakrypt" ../../libakrypt-0.x
make clean && make
wine ./example-intro.exe
cd ..
echo -e "\n"
read -p "press return key ..."

# Сборка ellcc под Win64 -----------
mkdir -p build-mingw64
cd build-mingw64
rm -f CMakeCache.txt
echo "Compiling by ecc (mingw64 on Windows)"
cmake -DCMAKE_C_COMPILER=ecc -DCMAKE_C_FLAGS="-target x86_64-w64-mingw32" -DLIBAKRYPT_EXT=".exe" -DLIBAKRYPT_CONF="C:/Users/Default/AppData/Roaming/libakrypt" ../../libakrypt-0.x
make clean && make
wine ./example-intro.exe
cd ..
echo -e "\n"
read -p "press return key ..."

# Сборка ellcc под ARMv7 ---------------------
mkdir -p build-arm32v7
cd build-arm32v7
echo "Compiling by ecc (arm32v7-linux, little endian)"
cmake -DCMAKE_C_COMPILER=ecc -DCMAKE_C_FLAGS="-target arm32v7-linux" ../../libakrypt-0.x
make clean && make
qemu-arm ./example-intro
cd ..
echo -e "\n"
read -p "press return key ..."

# Сборка ellcc под ARMv7eb ---------------------
mkdir -p build-arm32v7eb
cd build-arm32v7eb
echo "Compiling by ecc (arm32v7eb-linux, big endian)"
cmake -DCMAKE_C_COMPILER=ecc -DCMAKE_C_FLAGS="-target arm32v7eb-linux" -DLIBAKRYPT_BIG_ENDIAN=ON ../../libakrypt-0.x
make clean && make
qemu-armeb ./example-intro
cd ..
echo -e "\n"
read -p "press return key ..."

# Сборка ellcc под PPC32-Linux ---------------------
mkdir -p build-ppc32
cd build-ppc32
rm -f CMakeCache.txt
echo "Compiling by ecc (ppc32-linux, big-endian)"
cmake -DCMAKE_C_COMPILER=ecc -DCMAKE_C_FLAGS="-target ppc32-linux" -DLIBAKRYPT_BIG_ENDIAN=ON ../../libakrypt-0.x
make clean && make
qemu-ppc ./example-intro
cd ..
echo -e "\n\n"
