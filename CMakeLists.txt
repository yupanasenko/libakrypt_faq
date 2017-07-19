# -------------------------------------------------------------------------------------------------- #
# сборка по умолчанию
# cmake path && make
# где path это путь к каталогу, в котором расположен файл MakeLists.txt

# сборка с использованием с использованием clang
# cmake -D CMAKE_C_COMPILER=clang path && make

# сборка с использованием с использованием TinyCC
# cmake -D CMAKE_C_COMPILER=tcc path && make

# сборка при помощи MSVC из консоли (Visual Studio Console Prompt)
# cmake -G "NMake Makefiles" path && nmake

# сборка при MinGW из консоли MSYS (WINDOWS)
# cmake -G "MinGW Makefiles" -D CMAKE_C_COMPILER=gcc path && mingw32-make
# -------------------------------------------------------------------------------------------------- #
cmake_minimum_required( VERSION 2.8 )
project( libakrypt )
set( HEAD_VERSION 0 )
set( MAIN_VERSION 5 )
set( MINOR_VERSION 2 )

set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# для включения опции cmake -D LIBAKRYPT_GMP_TESTS=ON path
option( LIBAKRYPT_STATIC_LIB "Build the static library" ON )
option( LIBAKRYPT_SHARED_LIB "Build the shared library" OFF )
option( LIBAKRYPT_GMP_TESTS "Build test programs with libGMP" OFF)

# -------------------------------------------------------------------------------------------------- #
# множество исходных текстов библиотеки
set( MAIN_HEADER    source/libakrypt.h )

set( HEADERS        source/ak_tools.h
                    source/ak_context_manager.h
                    source/ak_buffer.h
                    source/ak_random.h
                    source/ak_oid.h )

set( SOURCES        source/ak_log.c
                    source/ak_libakrypt.c
                    source/ak_tools.c
                    source/ak_context_manager.c
                    source/ak_buffer.c
                    source/ak_random.c
                    source/ak_oid.c )

set( DOCS           doc/libakrypt.dox
                    doc/refman_header.in
                    doc/refman_footer.in
                    doc/Doxyfile.in )

set( CMAKES         cmake/DetectHeaders.cmake
                    cmake/DetectFlags.cmake
                    cmake/DetectLibraries.cmake
                    cmake/MakeDoc.cmake
                    cmake/MakeDist.cmake
                    cmake/MakeInstall.cmake )

set( OTHERS         CMakeLists.txt
                    Readme.md
                    Changelog.md
                    libakrypt.rc.in
                    libakrypt.conf
                    libakrypt-run.sh )

set( AKRYPT_SOURCES akrypt/akrypt.c
                    akrypt/akrypt_oid.c )
set( AKRYPT_FILES   akrypt/akrypt.h
                    akrypt/akrypt.1
                    akrypt/getopt.h
                    akrypt/getopt.c )

# -------------------------------------------------------------------------------------------------- #
# подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectHeaders )
include( DetectLibraries )
include( DetectFlags )

# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_CONF )
else()
  set( LIBAKRYPT_CONF "/etc" )
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка библиотек - статической и, если нужно, динамической
include_directories( "./source" )
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
if( LIBAKRYPT_CONF )
    message("-- Path for libakrypt.conf is ${LIBAKRYPT_CONF}")
    add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${LIBAKRYPT_CONF}" )
endif()

if( LIBAKRYPT_SHARED_LIB )
  add_library( akrypt-shared SHARED ${MAIN_HEADER} ${SOURCES} )
  set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  target_link_libraries( akrypt-shared ${LIBAKRYPT_LIBS} )
endif()
#
if( LIBAKRYPT_STATIC_LIB )
  add_library( akrypt-static STATIC ${MAIN_HEADER} ${SOURCES} )
  set_target_properties( akrypt-static PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка консольной утилиты
add_executable( akrypt${LIBAKRYPT_EXT} ${AKRYPT_SOURCES} )
target_include_directories( akrypt${LIBAKRYPT_EXT} PUBLIC "./akrypt" )
target_link_libraries( akrypt${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )

# -------------------------------------------------------------------------------------------------- #
# сборка тестовых примеров
set( EXAMPLES_LIST intro
                   log
                   random
                   randomize
                   random-system
                   oid )

# организуем сборку примеров со статической линковкой
if( LIBAKRYPT_STATIC_LIB )
  foreach( programm ${EXAMPLES_LIST} )
     add_executable( example-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
     target_link_libraries( example-${programm}${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
  endforeach()
endif()

# организуем сборку примеров с динамической линковкой
if( LIBAKRYPT_SHARED_LIB )
  foreach( programm ${EXAMPLES_LIST} )
     add_executable( example-dynamic-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
     target_link_libraries( example-dynamic-${programm}${LIBAKRYPT_EXT} akrypt-shared ${LIBAKRYPT_LIBS} )
  endforeach()
endif()

# теперь примеры, использующие неэкспортируемые функции
set( INTERNAL_EXAMPLES_LIST
                   context-manager-node
                   context-manager )

if( CMAKE_HOST_UNIX )
  foreach( programm ${INTERNAL_EXAMPLES_LIST} )
    add_executable( example-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
    target_link_libraries( example-${programm}${LIBAKRYPT_EXT} akrypt-static )
  endforeach()
endif()

# -------------------------------------------------------------------------------------------------- #
if( CMAKE_HOST_UNIX )
  include( MakeDoc )
  include( MakeDist )
endif()
include( MakeInstall )

# -------------------------------------------------------------------------------------------------- #

message("-- Compiler options is ${CMAKE_C_FLAGS}" )
# -------------------------------------------------------------------------------------------------- #
