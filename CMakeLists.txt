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
set( MINOR_VERSION 9 )

set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# для включения опции: cmake -D LIBAKRYPT_GMP_TESTS=ON path
option( LIBAKRYPT_STATIC_LIB "Build the static library" ON )
option( LIBAKRYPT_SHARED_LIB "Build the shared library" OFF )
option( LIBAKRYPT_INTERNAL_TESTS "Build collection of internal tests using non-export functions" OFF )
option( LIBAKRYPT_GMP_TESTS "Build comparison tests for gmp and libakrypt" OFF )
option( LIBAKRYPT_HTML_DOC "Build documentation in HTML format" OFF )

# -------------------------------------------------------------------------------------------------- #
# множество исходных текстов библиотеки и вспомогательных файлов
set( MAIN_HEADER    source/libakrypt.h )

set( HEADERS        source/ak_tools.h
                    source/ak_buffer.h
                    source/ak_oid.h
                    source/ak_random.h
                    source/ak_mpzn.h
                    source/ak_curves.h
                    source/ak_parameters.h
                    source/ak_gf2n.h
)

set( SOURCES        source/ak_tools.c
                    source/ak_buffer.c
                    source/ak_oid.c
                    source/ak_mpzn.c
                    source/ak_curves.c
                    source/ak_random.c
                    source/ak_gf2n.c
                    source/ak_libakrypt.c
)

# -------------------------------------------------------------------------------------------------- #
# подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectHeaders )
include( DetectLibraries )
include( DetectIntrinsics )

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
include_directories( "source" )
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
message("-- Compiler options is ${CMAKE_C_FLAGS}" )
if( LIBAKRYPT_LIBS )
  message("-- Additional libraries is ${LIBAKRYPT_LIBS}" )
endif()

# -------------------------------------------------------------------------------------------------- #
# тестовые примеры для арифметических операций
set( ARITHMETIC_TESTS_LIST
                 mpzn-convert
                 mpzn-arithmetic
                 mpzn-montgomery
                 mpzn-rem
                # mpzn-password
)

if( LIBAKRYPT_GMP_TESTS )
  enable_testing()
  if( LIBAKRYPT_STATIC_LIB )
    foreach( programm ${ARITHMETIC_TESTS_LIST} )
       add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
       target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt-static gmp )
       add_test( NAME test-${programm} COMMAND test-${programm}${LIBAKRYPT_EXT} )
    endforeach()
  endif()
  message("-- Added tests for integer arithmetic and comparizon with libgmp (now \"make test\" enabled)")
endif()

# -------------------------------------------------------------------------------------------------- #
# сборка примеров, иллюстрирующих работу с внешним интерфейсом библиотеки
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
                 internal-oid01
                 internal-oid03
                 # internal-random02
                 # internal-oid02
)

if( LIBAKRYPT_INTERNAL_TESTS )
  enable_testing()

  # добавляем примеры в случае сборки статической библиотеки
  if( LIBAKRYPT_STATIC_LIB )
    foreach( programm ${INTERNAL_TEST_LIST} )
       add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
       target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt-static ${LIBAKRYPT_LIBS} )
       add_test( NAME test-${programm}${LIBAKRYPT_EXT} COMMAND test-${programm}${LIBAKRYPT_EXT} )
    endforeach()
  endif()
  message("-- Added tests for internal functions (now \"make test\" enabled)")
endif()

# -------------------------------------------------------------------------------------------------- #
if( CMAKE_HOST_UNIX )
  include( MakeDoc )
endif()
