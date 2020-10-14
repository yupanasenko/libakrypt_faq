# -------------------------------------------------------------------------------------------------- #
# Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru
#
# CMakeLists.txt
# -------------------------------------------------------------------------------------------------- #
cmake_minimum_required( VERSION 2.8 FATAL_ERROR )

# -------------------------------------------------------------------------------------------------- #
set( HEAD_VERSION 0 )
set( MAIN_VERSION 9 )
set( MINOR_VERSION 1 )
set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# -------------------------------------------------------------------------------------------------- #
# Формируем название проекта
project( libakrypt-${FULL_VERSION} C )

# -------------------------------------------------------------------------------------------------- #
# Перечень доступных опций для сборки библиотеки
option( AK_STATIC_LIB "Build the static library" ON )
option( AK_SHARED_LIB "Build the shared library" ON )
option( AK_HAVE_LIBAKRYPT "Build crypto library" ON )
option( LIBAKRYPT_GMP_TESTS "Build comparison tests for gmp and libakrypt" OFF )
# LIBAKRYPT_CONF

if( LIBAKRYPT_GMP_TESTS )
  find_library( GMP_LIB gmp )
  if( GMP_LIB )
    set( AK_HAVE_LIBAKRYPT ON )
    set( AK_STATIC_LIB ON )
    message("-- Found libgmp: ${GMP_LIB}" )
  else()
    set( LIBAKRYPT_GMP_TESTS OFF )
    message("-- libgmp not found" )
  endif()

endif()

# -------------------------------------------------------------------------------------------------- #
# подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectHeaders )
include( DetectIntrinsics )

# -------------------------------------------------------------------------------------------------- #
# вырабатываем заголовочный файл
configure_file( ${CMAKE_SOURCE_DIR}/source/libakrypt-base.h.in ${CMAKE_SOURCE_DIR}/source/libakrypt-base.h @ONLY )
message("-- Generation of libakrypt-base.h is done")

# -------------------------------------------------------------------------------------------------- #
# Определяем базовое множество исходных текстов библиотеки
set( MAIN_HEADERS source/libakrypt-base.h )
if( AK_HAVE_LIBAKRYPT )
  set( MAIN_HEADERS ${MAIN_HEADERS} source/libakrypt.h )
endif()

# -------------------------------------------------------------------------------------------------- #
set( AKBASE_SOURCES
   source/ak_tools.c
   source/ak_ini.c
   source/ak_list.c
   source/ak_file.c
   source/ak_base64.c
  )

# -------------------------------------------------------------------------------------------------- #
# Добавляем исходные тексты для криптобиблиотеки
if( AK_HAVE_LIBAKRYPT )
 set( AKRYPT_SOURCES
    source/ak_options.c
    source/ak_libakrypt.c
    source/ak_oid.c
    source/ak_random.c
    source/ak_gf2n.c
    source/ak_mpzn.c
    source/ak_curves.c
    source/ak_parameters.c
    source/ak_mac.c
    source/ak_hash.c
    source/ak_skey.c
    source/ak_hmac.c
    source/ak_bckey.c
    source/ak_magma.c
    source/ak_kuznechik.c
 )
endif()

# -------------------------------------------------------------------------------------------------- #
# проверка архитектуры
include( TestBigEndian )
TEST_BIG_ENDIAN( IS_BIG_ENDIAN )
if( IS_BIG_ENDIAN )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_BIG_ENDIAN" )
else()
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_LITTLE_ENDIAN" )
endif()
message("-- Used compile flags ${CMAKE_C_FLAGS}")

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
# Определем процедуры сборки библиотек - статической или динамической
include_directories( "source" )
add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${LIBAKRYPT_CONF}" )
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
add_compile_options( -DLIBAKRYPT_COMPILER_NAME="${CMAKE_C_COMPILER}" )
add_compile_options( -DLIBAKRYPT_COMPILER_VERSION="${CMAKE_C_COMPILER_VERSION}" )

if( AK_SHARED_LIB )
  add_library( akbase-shared SHARED ${MAIN_HEADERS} ${AKBASE_SOURCES} )
  set_target_properties( akbase-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  set_target_properties( akbase-shared PROPERTIES OUTPUT_NAME akrypt-base CLEAN_DIRECT_CUSTOM 1 )
  message( "-- Building libakrypt-base: shared library" )
  if( AK_HAVE_LIBAKRYPT )
    add_library( akrypt-shared SHARED ${MAIN_HEADERS} ${AKRYPT_SOURCES} )
    set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
    set_target_properties( akrypt-shared PROPERTIES OUTPUT_NAME akrypt CLEAN_DIRECT_CUSTOM 1 )
    target_link_libraries( akrypt-shared akbase-shared )
    message( "-- Building libakrypt: shared library" )
  endif()
endif()

#
if( AK_STATIC_LIB )
  add_library( akbase-static STATIC ${MAIN_HEADERS} ${AKBASE_SOURCES} )
  set_target_properties( akbase-static PROPERTIES OUTPUT_NAME akrypt-base CLEAN_DIRECT_CUSTOM 1 )
  message( "-- Building libakrypt-base: static library" )
  if( AK_HAVE_LIBAKRYPT )
    add_library( akrypt-static STATIC ${MAIN_HEADERS} ${AKRYPT_SOURCES} )
    set_target_properties( akrypt-static PROPERTIES OUTPUT_NAME akrypt CLEAN_DIRECT_CUSTOM 1 )
    message( "-- Building libakrypt: shared library" )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# Сборка примеров, иллюстрирующих работу базовой библиотеки
# -------------------------------------------------------------------------------------------------- #
set( EXAMPLES_LIST
     log
     ini
     file
   )

foreach( programm ${EXAMPLES_LIST} )
  if( AK_STATIC_LIB )
    add_executable( example-${programm} examples/example-${programm}.c )
    target_link_libraries( example-${programm} akbase-static )
  endif()
  if( AK_SHARED_LIB )
    add_executable( example-shared-${programm} examples/example-${programm}.c )
    target_link_libraries( example-shared-${programm} akbase-shared )
  endif()
endforeach()

# -------------------------------------------------------------------------------------------------- #
# Сборка тестовых примеров, проверяющих корректность элементарных арифметических операций
set ( ARITHMETIC_TESTS_LIST
      random01
      gf2n
    )

if( LIBAKRYPT_GMP_TESTS )
  set( ARITHMETIC_TESTS_LIST ${ARITHMETIC_TESTS_LIST}
       mpzn-arithmetic
       mpzn-convert
       mpzn-montgomery
       mpzn-rem
     )
endif()

enable_testing()
foreach( programm ${ARITHMETIC_TESTS_LIST} )
  add_executable( test-${programm} examples/test-${programm}.c )
  target_link_libraries( test-${programm} akrypt-static akbase-static ${GMP_LIB} )
  add_test( NAME test-${programm} COMMAND test-${programm} )
endforeach()
message("-- Added tests (now \"make test\" enabled)")
message("   -- ${ARITHMETIC_TESTS_LIST}" )

# -------------------------------------------------------------------------------------------------- #
# Сборка большого примера для функций криптобиблиотеки -- утилиты aktool
# -------------------------------------------------------------------------------------------------- #
set( AKTOOL_SOURCES
     aktool/aktool.c
     aktool/aktool_show.c
     aktool/aktool_test.c
   )
set( AKTOOL_FILES
     aktool/aktool.h
     aktool/getopt.h
     aktool/getopt.c
   )

# -------------------------------------------------------------------------------------------------- #
if( AK_HAVE_GETOPT_H )
else()
  set( AKTOOL_SOURCES ${AKTOOL_SOURCES} aktool/getopt.c )
endif()
message("-- Sources for aktool" )
message("   -- ${AKTOOL_SOURCES}" )

find_path( AK_HAVE_LIBINTL_H NAMES libintl.h )
if( AK_HAVE_LIBINTL_H )
  include_directories( ${AK_HAVE_LIBINTL_H} )
  message("-- Additional header for aktool is libintl.h" )
endif()

add_executable( aktool ${AKTOOL_SOURCES} )
target_include_directories( aktool PUBLIC "aktool" )

find_library( LIBINTL_LIB intl )
if( LIBINTL_LIB )
  message("-- Additional library for aktool is ${LIBINTL_LIB}")
  target_link_libraries( aktool akrypt-static akbase-static ${LIBINTL_LIB} ${GMP_LIB} )
 else()
  target_link_libraries( aktool akrypt-static akbase-static ${GMP_LIB} )
endif()

# -------------------------------------------------------------------------------------------------- #
# Сборка документации и завершающие настройки
 include( MakeDoc )

# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
if( CMAKE_HOST_UNIX )
  if( AK_STATIC_LIB )
    install( TARGETS akbase-static
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
    if( AK_HAVE_LIBAKRYPT )
      install( TARGETS akrypt-static
               LIBRARY DESTINATION lib
               ARCHIVE DESTINATION lib
             )
    endif()
  endif()

  if( AK_SHARED_LIB )
    install( TARGETS akbase-shared
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
    if( AK_HAVE_LIBAKRYPT )
      install( TARGETS akrypt-shared
               LIBRARY DESTINATION lib
               ARCHIVE DESTINATION lib
             )
    endif()
  endif()

  install( FILES ${MAIN_HEADERS} DESTINATION include )
endif()

# -------------------------------------------------------------------------------------------------- #
set( CPACK_GENERATOR "DEB" )
set( CPACK_SOURCE_GENERATOR "TBZ2")
set( CPACK_DEBIAN_PACKAGE_DEPENDS "libc" )

set( CPACK_DEBIAN_PACKAGE_MAINTAINER "Axel Kenzo") #required
set( CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/Readme.md")

include(CPack)

# -------------------------------------------------------------------------------------------------- #
#                                                                                    CMakeLists.txt
# -------------------------------------------------------------------------------------------------- #
