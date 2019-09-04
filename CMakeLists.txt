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
project( libakrypt C )
cmake_minimum_required( VERSION 2.7 FATAL_ERROR )

set( HEAD_VERSION 0 )
set( MAIN_VERSION 8 )
set( MINOR_VERSION 1 )

set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# -------------------------------------------------------------------------------------------------- #
# Перечень доступных опций для сборки библиотеки
# - для включения опции: cmake -D LIBAKRYPT_GMP_TESTS=ON path
# -------------------------------------------------------------------------------------------------- #
option( LIBAKRYPT_STATIC_LIB "Build the static library" OFF )
option( LIBAKRYPT_SHARED_LIB "Build the shared library" ON )
option( LIBAKRYPT_CRYPTO_FUNCTIONS "Build library with crypto functions" ON )
option( LIBAKRYPT_CONST_CRYPTO_PARAMS "Build library with const values of crypto parameters" OFF )
option( LIBAKRYPT_INTERNAL_TESTS "Build collection of internal tests using non-export functions" OFF )
option( LIBAKRYPT_GMP_TESTS "Build comparison tests for gmp and libakrypt" OFF )
option( LIBAKRYPT_HTML_DOC "Build documentation in HTML format" OFF )
option( LIBAKRYPT_PDF_DOC "Build documentation in PDF format" OFF )

# -------------------------------------------------------------------------------------------------- #
# Уточнение зависимостей между опциями
# - допускается одновременная сборка либо статической, либо разделяемой библиотеки
# - (по умолчанию собирается статическая версия библиотеки)
# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_INTERNAL_TESTS OR LIBAKRYPT_GMP_TESTS )
  set( LIBAKRYPT_STATIC_LIB ON )
  set( LIBAKRYPT_SHARED_LIB OFF )
endif()
if( LIBAKRYPT_STATIC_LIB )
  set( LIBAKRYPT_SHARED_LIB OFF )
endif()

# -------------------------------------------------------------------------------------------------- #
# Определяем базовое множество исходных текстов библиотеки
# -------------------------------------------------------------------------------------------------- #
set( MAIN_HEADER    source/libakrypt.h )

set( HEADERS        source/ak_tools.h
                    source/ak_oid.h
                    source/ak_random.h
                    source/ak_mpzn.h
                    source/ak_curves.h
                    source/ak_parameters.h
                    source/ak_gf2n.h
)

set( SOURCES        source/ak_tools.c
                    source/ak_oid.c
                    source/ak_mpzn.c
                    source/ak_curves.c
                    source/ak_random.c
                    source/ak_gf2n.c
                    source/ak_libakrypt.c
)

# -------------------------------------------------------------------------------------------------- #
# Добавляем исходные тексты базовых криптографических примитивов
# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_CRYPTO_FUNCTIONS )
  set( HEADERS      ${HEADERS}
                    source/ak_mac.h
                    source/ak_hash.h
     )

  set( SOURCES      ${SOURCES}
                    source/ak_mac.c
                    source/ak_hash.c
     )
endif()

# -------------------------------------------------------------------------------------------------- #
# Определяем базовое множество вспомогательных и служебных файлов
# -------------------------------------------------------------------------------------------------- #
set( CMAKES         cmake/DetectFlags.cmake
                    cmake/DetectHeaders.cmake
                    cmake/DetectIntrinsics.cmake
                    cmake/DetectLibraries.cmake
                    cmake/MakeDist.cmake
                    cmake/MakeDoc.cmake
                    cmake/MakeInstall.cmake
)

set( DOCS           doc/00-introduction.md
                    doc/01-install-guide.md
                    doc/02-principles.md
                    doc/Doxyfile.in
                    doc/refman_footer.in
                    doc/refman_header.in
)

set( OTHERS         CMakeLists.txt
                    Readme.md
                    Changelog.md
                    libakrypt.conf
                    libakrypt.rc.in
                    LICENSE
)

# -------------------------------------------------------------------------------------------------- #
# подключаем модули CMake для тонкой настройки параметров сборки
# -------------------------------------------------------------------------------------------------- #
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectHeaders )
include( DetectLibraries )
include( DetectIntrinsics )

# -------------------------------------------------------------------------------------------------- #
# Определяем место хранения файла с  настройками библиотеки
# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_CONF )
else()
  if( CMAKE_HOST_UNIX )
    set( LIBAKRYPT_CONF "/etc" )
  endif()
  if( WIN32 )
    set( LIBAKRYPT_CONF "C:\\\\Program Files\\\\Akrypt" )
  endif()
endif()
message("-- Path for libakrypt.conf is ${LIBAKRYPT_CONF}")

# -------------------------------------------------------------------------------------------------- #
# Добавляем флаг сборки библиотеки без поддержки функций чтения настроек
# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_CONST_CRYPTO_PARAMS )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_CONST_CRYPTO_PARAMS" )
endif()

# -------------------------------------------------------------------------------------------------- #
# Добавляем поддержку криптографических функций
# ------------------------------------------------------------------------- ------------------------- #
if( LIBAKRYPT_CRYPTO_FUNCTIONS )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_CRYPTO_FUNCTIONS" )
endif()


# -------------------------------------------------------------------------------------------------- #
# Определем процедуры сборки библиотек - статической или динамической
# -------------------------------------------------------------------------------------------------- #
include_directories( "source" )
add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${LIBAKRYPT_CONF}" )
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )

if( LIBAKRYPT_SHARED_LIB )
  add_library( akrypt SHARED ${MAIN_HEADER} ${SOURCES} ${ASN1_SOURCES} )
  set_target_properties( akrypt PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  target_link_libraries( akrypt ${LIBAKRYPT_LIBS} )
  message( "-- Building a shared library" )
endif()
#
if( LIBAKRYPT_STATIC_LIB )
  add_library( akrypt STATIC ${MAIN_HEADER} ${SOURCES} ${ASN1_SOURCES} )
  set_target_properties( akrypt PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  message( "-- Building a static library" )
endif()

# -------------------------------------------------------------------------------------------------- #
# Информация о флагах компиляции и дополнительных библиотеках
# -------------------------------------------------------------------------------------------------- #
message("-- Compiler options is ${CMAKE_C_FLAGS}" )
if( LIBAKRYPT_LIBS )
  message("-- Additional libraries is ${LIBAKRYPT_LIBS}" )
endif()

# -------------------------------------------------------------------------------------------------- #
# Сборка примеров, иллюстрирующих работу с внешним интерфейсом библиотеки
# -------------------------------------------------------------------------------------------------- #
set( EXAMPLES_LIST hello
                   log
)
if( LIBAKRYPT_CRYPTO_FUNCTIONS )
  set( EXAMPLES_LIST ${EXAMPLES_LIST}

  )
endif()

foreach( programm ${EXAMPLES_LIST} )
  add_executable( example-${programm}${LIBAKRYPT_EXT} examples/example-${programm}.c )
  target_link_libraries( example-${programm}${LIBAKRYPT_EXT} akrypt ${LIBAKRYPT_LIBS} )
endforeach()

# -------------------------------------------------------------------------------------------------- #
# Добавляем исходные тексты примеров, иллюстрирующих работу с внутренним интерфейсом библиотеки
# -------------------------------------------------------------------------------------------------- #
set( INTERNAL_TEST_LIST
                 gf2n
                 mpzn01
                 oid01
                 oid02
                 random01
)
if( LIBAKRYPT_CRYPTO_FUNCTIONS )
  set( INTERNAL_TEST_LIST ${INTERNAL_TEST_LIST}
                 hash01a
  )
  set( INTERNAL_TEST_LIST_EXAMPLES # эти программы компилируются, но не вызываются
                                   # при запуске make test
  )
  if( LIBAKRYPT_HAVE_SYSUN )
    set( INTERNAL_TEST_LIST_EXAMPLES
                 ${INTERNAL_TEST_LIST_EXAMPLES}
    )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# Сборка примеров, иллюстрирующих работу с внутренним интерфейсом библиотеки
# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_INTERNAL_TESTS )

  # добавляем примеры только в случае сборки статической библиотеки
  if( LIBAKRYPT_STATIC_LIB )
    enable_testing()
    foreach( programm ${INTERNAL_TEST_LIST} )
       add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
       target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt ${LIBAKRYPT_LIBS} )
       add_test( NAME test-${programm}${LIBAKRYPT_EXT} COMMAND test-${programm}${LIBAKRYPT_EXT} )
    endforeach()
    # компилируемые тесты, не попадающие в вызов команды make test
    foreach( programm ${INTERNAL_TEST_LIST_EXAMPLES} )
       add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
       target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt ${LIBAKRYPT_LIBS} )
    endforeach()
    message("-- Added tests for internal functions (now \"make test\" enabled): ")
    message("   - ${INTERNAL_TEST_LIST}" )
    if( ${INTERNAL_TEST_LIST_EXAMPLES} )
      message("   - ${INTERNAL_TEST_LIST_EXAMPLES}" )
    endif()
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# Добавляем исходные тексты примеров, тестирующих арифметические операции
# -------------------------------------------------------------------------------------------------- #
set( ARITHMETIC_TESTS_LIST
                 mpzn-convert
                 mpzn-arithmetic
                 mpzn-montgomery
                 mpzn-rem
)

# -------------------------------------------------------------------------------------------------- #
# Сборка арифметических тестов
# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_GMP_TESTS )
  if( LIBAKRYPT_CRYPTO_FUNCTIONS )
    set( ARITHMETIC_TESTS_LIST ${ARITHMETIC_TESTS_LIST} mpzn-password )
  endif()

  # добавляем примеры только в случае сборки статической библиотеки
  if( LIBAKRYPT_STATIC_LIB )
    enable_testing()
    foreach( programm ${ARITHMETIC_TESTS_LIST} )
      add_executable( test-${programm}${LIBAKRYPT_EXT} tests/test-${programm}.c )
      target_link_libraries( test-${programm}${LIBAKRYPT_EXT} akrypt gmp )
      add_test( NAME test-${programm} COMMAND test-${programm}${LIBAKRYPT_EXT} )
    endforeach()
    message("-- Added tests for integer arithmetic and comparizon with libgmp (now \"make test\" enabled):")
    message("   - ${ARITHMETIC_TESTS_LIST}" )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# Сборка документации и завершающие настройки
# -------------------------------------------------------------------------------------------------- #
include( MakeDoc )
