# -------------------------------------------------------------------------------------------------- #
# поиск зависимостей Unix
if( CMAKE_HOST_UNIX )
  find_library( PTHREAD pthread )
  if( PTHREAD )
     set( PTHREAD_LIB pthread )
     message("-- Searching libpthread - done ")
  else()
     message("-- libpthread not found")
     return()
  endif()
  if( LIBAKRYPT_CONF )
  else()
    set( LIBAKRYPT_CONF "/etc" )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# поиск зависомостей под Вындоус MSVC
if( MSVC )
  find_library( PTHREAD pthreadVC2 )
  if( PTHREAD )
     set( PTHREAD_LIB pthreadVC2 )
     message("-- Searching pthreadVC2 - done ")
     check_c_source_compiles("
       #include <pthread.h>
       int main( void ) {
       return 0;
     }" LIBAKRYPT_HAVE_STRUCT_TIMESPEC )
     if( LIBAKRYPT_HAVE_STRUCT_TIMESPEC )
     else()
       set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_STRUCT_TIMESPEC" )
     endif()
  else()
     message("-- pthreadVC2 not found")
     return()
  endif()
  configure_file( ${CMAKE_SOURCE_DIR}/libakrypt.rc.in ${CMAKE_SOURCE_DIR}/libakrypt.rc @ONLY )
  set( SOURCES ${SOURCES} "libakrypt.rc" )
  set( CMAKE_BUILD_TYPE "Release" )
endif()

# -------------------------------------------------------------------------------------------------- #
# поиск зависимостей MinGW
if( MSYS )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMSYS" )
endif()
