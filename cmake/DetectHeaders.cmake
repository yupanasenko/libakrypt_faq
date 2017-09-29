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
  #include <fcntl.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_FCNTL )

if( LIBAKRYPT_HAVE_FCNTL )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_FCNTL_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <limits.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_LIMITS )

if( LIBAKRYPT_HAVE_LIMITS )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_LIMITS_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <sys/mman.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_SYSMMAN )

if( LIBAKRYPT_HAVE_SYSMMAN )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_SYSMMAN_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <sys/stat.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_SYSSTAT )

if( LIBAKRYPT_HAVE_SYSSTAT )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_SYSSTAT_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <errno.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_ERRNO )

if( LIBAKRYPT_HAVE_ERRNO )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_ERRNO_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <termios.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_TERMIOS )

if( LIBAKRYPT_HAVE_TERMIOS )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_TERMIOS_H" )
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

# -------------------------------------------------------------------------------------------------- #
if( WIN32 )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_WINDOWS_H" )
endif()

# -------------------------------------------------------------------------------------------------- #

