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
  set( LIBAKRYPT_OPTIONS_PATH "/etc" )
  if( LIBAKRYPT_CONF )
    set( LIBAKRYPT_OPTIONS_PATH ${LIBAKRYPT_CONF} )
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
# поиск зависомостей под Вындоус MSVC
if( MSVC )
  find_library( PTHREAD pthreadVC2 )
  if( PTHREAD )
     set( PTHREAD_LIB pthreadVC2 )
     message("-- Searching pthreadVC2 - done ")
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
