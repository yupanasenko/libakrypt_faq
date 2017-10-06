# -------------------------------------------------------------------------------------------------- #
include(CheckCSourceCompiles)

# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <sys/types.h>
  int main( void ) {
    u_int64_t w1, w0, u = 1, v = 2;
    __asm__ (\"mulq %3\" : \"=a,a\" (w0), \"=d,d\" (w1) : \"%0,0\" (u), \"r,m\" (v));
    return 0;
  }" LIBAKRYPT_HAVE_BUILTIN_MULQ_GCC )

if( LIBAKRYPT_HAVE_BUILTIN_MULQ_GCC )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_BUILTIN_MULQ_GCC" )
endif()

# -------------------------------------------------------------------------------------------------- #
