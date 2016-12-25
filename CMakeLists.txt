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
# cmake -G "MinGW Makefiles" path && make
# -------------------------------------------------------------------------------------------------- #
cmake_minimum_required( VERSION 2.8 )
project( libakrypt )
set( HEAD_VERSION 0 )
set( MAIN_VERSION 4 )
set( MINOR_VERSION 25 )

set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# -------------------------------------------------------------------------------------------------- #
# описание исходных кодов
set( MAIN_HEADER source/libakrypt.h )
set( HEADERS source/ak_buffer.h
             source/ak_oid.h
             source/ak_hash.h
             source/ak_random.h
             source/ak_skey.h
             source/ak_parameters.h
             source/ak_libakrypt.h
             source/ak_keylist.h
             source/ak_mpzn.h
             source/ak_curves.h )
set( SOURCES source/ak_log.c
             source/ak_libakrypt.c
             source/ak_buffer.c
             source/ak_oid.c
             source/ak_hash.c
             source/ak_streebog.c
             source/ak_sha.c
             source/ak_gosthash.c
             source/ak_random.c
             source/ak_skey.c
             source/ak_magma.c
             source/ak_kuznetchik.c
             source/ak_keylist.c
             source/ak_mpzn.c
             source/ak_curves.c )
set( DOCS    doc/libakrypt.dox
             doc/Doxyfile.in )
set( CMAKES  cmake/DetectFlags.cmake
             cmake/DetectIntrinsics.cmake
             cmake/FindRelations.cmake
             cmake/MakeDist.cmake
             cmake/MakeDoc.cmake )
set( OTHERS  CMakeLists.txt
             libakrypt.rc.in
             libakrypt.conf
             TODO )

# -------------------------------------------------------------------------------------------------- #
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectIntrinsics )
include( FindRelations )

# -------------------------------------------------------------------------------------------------- #
# сборка библиотек
include_directories( "./source" )
if( LIBAKRYPT_OPTIONS_PATH )
    message("-- Path for libakrypt.conf is ${LIBAKRYPT_OPTIONS_PATH}")
    #set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_OPTIONS_PATH=${LIBAKRYPT_OPTIONS_PATH}" )
    add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${LIBAKRYPT_OPTIONS_PATH}" )
endif()
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
#
add_library( akrypt-shared SHARED ${MAIN_HEADER} ${SOURCES} )
set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
target_link_libraries( akrypt-shared ${PTHREAD_LIB} )
add_library( akrypt-static STATIC ${MAIN_HEADER} ${SOURCES} )
set_target_properties( akrypt-static PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )

# -------------------------------------------------------------------------------------------------- #
# сборка тестовых примеров
set( EXAMPLES_LIST intro
                   log
                   oid
                   oid-magma
                   hash
                   hash-parts
                   hash-oids
                   random
                   dev-random
                   encrypt-ecb )
foreach( programm ${EXAMPLES_LIST} )
    # сборка статических примеров
    add_executable( example-${programm} examples/example-${programm}.c )
    target_link_libraries( example-${programm} akrypt-static ${PTHREAD_LIB} )
endforeach()

# -------------------------------------------------------------------------------------------------- #
# поиск gmp для отладки и тестирования арифметических операций
find_library( GMPLIB gmp )
if( GMPLIB )
   find_file( GMPLIB_H gmp.h )
   if( GMPLIB_H )
     message("-- Searching libgmp for special arithmetic tests is done")
     set( ARITHMETIC_TESTS_LIST mpzn-convert-to-gmp
                                mpzn-convert-to-hexstr
                                mpzn-random-modulo
                                mpzn-arithmetic )
     foreach( programm ${ARITHMETIC_TESTS_LIST} )
         # сборка статических примеров
         add_executable( example-${programm} examples/example-${programm}.c )
         target_link_libraries( example-${programm} akrypt-static ${PTHREAD_LIB} gmp )
     endforeach()
   endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# очистка служебной информации из статических примеров
add_custom_target( strip strip --strip-all ${CMAKE_BINARY_DIR}/example-* )

# -------------------------------------------------------------------------------------------------- #
include( MakeDist )
include( MakeDoc )
message("-- Compiler options is ${CMAKE_C_FLAGS}" )

# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
if( CMAKE_HOST_UNIX )
    install( TARGETS akrypt-shared akrypt-static
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
    install( FILES ${MAIN_HEADER} DESTINATION include )
    install( FILES libakrypt.conf DESTINATION ${LIBAKRYPT_OPTIONS_PATH} )
endif()

# -------------------------------------------------------------------------------------------------- #
