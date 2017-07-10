# -------------------------------------------------------------------------------------------------- #
if( MSVC )

  find_library( PTHREAD pthreadVC2 )
  if( PTHREAD )
    message("-- Searching pthreadVC2 - done ")
    set( LIBAKRYPT_LIBS pthreadVC2 )
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
    exit()
  endif()

endif()

if( WIN32 )
  configure_file( ${CMAKE_SOURCE_DIR}/libakrypt.rc.in ${CMAKE_SOURCE_DIR}/libakrypt.rc @ONLY )
  set( SOURCES ${SOURCES} libakrypt.rc )
  set( CMAKE_BUILD_TYPE "Release" )
endif()



#  find_library( PTHREAD pthreadVC2 )
#  if( PTHREAD )
#     set( PTHREAD_LIB pthreadVC2 )
#     message("-- Searching pthreadVC2 - done ")
#     check_c_source_compiles("
#       #include <pthread.h>
#       int main( void ) {
#       return 0;
#     }" LIBAKRYPT_HAVE_STRUCT_TIMESPEC )
#     if( LIBAKRYPT_HAVE_STRUCT_TIMESPEC )
#     else()
#       set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_STRUCT_TIMESPEC" )
#     endif()
#  else()
#     message("-- pthreadVC2 not found")
#     return()
#  endif()
#  configure_file( ${CMAKE_SOURCE_DIR}/libakrypt.rc.in ${CMAKE_SOURCE_DIR}/libakrypt.rc @ONLY )
#  set( SOURCES ${SOURCES} "libakrypt.rc" )
#  set( CMAKE_BUILD_TYPE "Release" )
# endif()
