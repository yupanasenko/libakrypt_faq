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
cmake_minimum_required( VERSION 3.2 )
project( libakrypt )

set( HEAD_VERSION 0 )
set( MAIN_VERSION 7 )
set( MINOR_VERSION 1 )

set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# для включения опции cmake -D LIBAKRYPT_GMP_TESTS=ON path
option( LIBAKRYPT_STATIC_LIB "Build the static library" ON )
option( LIBAKRYPT_SHARED_LIB "Build the shared library" OFF )
option( LIBAKRYPT_GMP_TESTS "Build library with comparison gmp and libakrypt tests" OFF )

# -------------------------------------------------------------------------------------------------- #
# множество исходных текстов библиотеки и вспомогательных файлов
set( MAIN_HEADER    source/libakrypt.h )

set( HEADERS        source/ak_tools.h
                    source/ak_buffer.h
                    source/ak_random.h
)

set( SOURCES        source/ak_tools.c
                    source/ak_buffer.c
                    source/ak_random.c
                    source/ak_libakrypt.c
)

set( DOCS           doc/refman_header.in
                    doc/refman_footer.in
                    doc/Doxyfile.in
                    doc/01-install-guide.md
                    doc/02-user-guide.md
                    doc/03-internal-interface.md )

set( CMAKES         cmake/DetectHeaders.cmake
                    cmake/DetectFlags.cmake
                    cmake/DetectLibraries.cmake
                    cmake/DetectIntrinsics.cmake
                    cmake/MakeDoc.cmake
                    cmake/MakeDist.cmake
                    cmake/MakeInstall.cmake )

set( OTHERS         CMakeLists.txt
                    LICENSE
                    Readme.md
                    Changelog.md
                    libakrypt.conf
                    libakrypt.rc.in
)

# -------------------------------------------------------------------------------------------------- #
# подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectHeaders )
include( DetectIntrinsics )
include( DetectLibraries )

# -------------------------------------------------------------------------------------------------- #
# определяемся с архитектурой
if( LIBAKRYPT_BIG_ENDIAN )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_BIG_ENDIAN" )
endif()

# -------------------------------------------------------------------------------------------------- #
# определяемся с местом хранения файла с конфигурацией библиотеки
if( LIBAKRYPT_CONF )
else()
  if( CMAKE_HOST_UNIX )
    set( LIBAKRYPT_CONF "/etc" )
  endif()
  if( WIN32 )
    set( LIBAKRYPT_CONF "C:/Program Files/Akrypt" )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка библиотек - статической и, если нужно, динамической
include_directories( "source " )
message("-- Path for libakrypt.conf is ${LIBAKRYPT_CONF}")
add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${LIBAKRYPT_CONF}" )
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
#
if( LIBAKRYPT_SHARED_LIB )
  add_library( akrypt-shared SHARED ${MAIN_HEADER} ${SOURCES} ${ASN1_SOURCES} )
  set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  target_link_libraries( akrypt-shared ${LIBAKRYPT_LIBS} )
endif()
#
if( LIBAKRYPT_STATIC_LIB )
  add_library( akrypt-static STATIC ${MAIN_HEADER} ${SOURCES} ${ASN1_SOURCES} )
  set_target_properties( akrypt-static PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
endif()

# -------------------------------------------------------------------------------------------------- #
message("-- Additional libraries is ${LIBAKRYPT_LIBS}" )

# -------------------------------------------------------------------------------------------------- #
enable_testing()

# сборка тестовых примеров
set( EXAMPLES_LIST hello
                   log
                   buffer
)

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

# -------------------------------------------------------------------------------------------------- #
# теперь примеры, использующие неэкспортируемые функции
set( INTERNAL_TEST_LIST
                   internal-random01
)

if( CMAKE_HOST_UNIX )
  foreach( programm ${INTERNAL_EXAMPLES_LIST} )
     add_executable( test-${programm}${LIBAKRYPT_EXT} examples/test-${programm}.c )
     target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
     add_test( NAME test-${programm}${LIBAKRYPT_EXT} COMMAND test-${programm}${LIBAKRYPT_EXT} )
  endforeach()
endif()

# -------------------------------------------------------------------------------------------------- #
if( UNIX )
  include( MakeDoc )
  include( MakeDist )
endif()
include( MakeInstall )

# -------------------------------------------------------------------------------------------------- #
message("-- Compiler options is ${CMAKE_C_FLAGS}" )

# -------------------------------------------------------------------------------------------------- #
