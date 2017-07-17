# -------------------------------------------------------------------------------------------------- #
include(CheckCSourceCompiles)

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <syslog.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_SYSLOG )

if( LIBAKRYPT_HAVE_SYSLOG )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_SYSLOG_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <unistd.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_UNISTD )

if( LIBAKRYPT_HAVE_UNISTD )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_UNISTD_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <getopt.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_GETOPT )

if( LIBAKRYPT_HAVE_GETOPT )
else()
  set( AKRYPT_SOURCES ${AKRYPT_SOURCES} akrypt/getopt.c )
endif()
