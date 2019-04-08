# -------------------------------------------------------------------------------------------------- #
include(CheckCSourceCompiles)

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <stdio.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_STDIO )

if( LIBAKRYPT_HAVE_STDIO )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_STDIO_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <stdlib.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_STDLIB )

if( LIBAKRYPT_HAVE_STDLIB )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_STDLIB_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <string.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_STRING )

if( LIBAKRYPT_HAVE_STRING )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_STRING_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <endian.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_ENDIAN )

if( LIBAKRYPT_HAVE_ENDIAN )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_ENDIAN_H" )
endif()


# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <time.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_TIME )

if( LIBAKRYPT_HAVE_TIME )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_TIME_H" )
endif()

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
  #include <sys/types.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_SYSTYPES )

if( LIBAKRYPT_HAVE_SYSTYPES )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_SYSTYPES_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <sys/socket.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_SYSSOCKET )

if( LIBAKRYPT_HAVE_SYSSOCKET )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_SYSSOCKET_H" )
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
  #include <dirent.h>
  int main( void ) {
     struct dirent st;
     st.d_type = 4;
     return 0;
  }" LIBAKRYPT_HAVE_DIRENT )

if( LIBAKRYPT_HAVE_DIRENT )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_DIRENT_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <fnmatch.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_FNMATCH )

if( LIBAKRYPT_HAVE_FNMATCH )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_FNMATCH_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <stdalign.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_STDALIGN )

if( LIBAKRYPT_HAVE_STDALIGN )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_STDALIGN_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <stdarg.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_STDARG )

if( LIBAKRYPT_HAVE_STDARG )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_STDARG_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <windows.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_WINDOWS )

if( LIBAKRYPT_HAVE_WINDOWS )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_WINDOWS_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <getopt.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_GETOPT )

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <locale.h>
  int main( void ) {
     setlocale( LC_ALL, \"\" );
     return 0;
  }" LIBAKRYPT_HAVE_LOCALE )

if( LIBAKRYPT_HAVE_LOCALE )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_LOCALE_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <libintl.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_LIBINTL )

if( LIBAKRYPT_HAVE_LIBINTL )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_LIBINTL_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <signal.h>
  int main( void ) {
     return 0;
  }" LIBAKRYPT_HAVE_SIGNAL )

if( LIBAKRYPT_HAVE_SIGNAL )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_SIGNAL_H" )
endif()

# -------------------------------------------------------------------------------------------------- #
