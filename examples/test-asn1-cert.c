 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>


 int main( int argc, char *argv[] )
{
  struct verifykey vkey;

  ak_libakrypt_create( ak_function_log_stderr );

  printf("verify: %d\n", ak_verifykey_import_from_certificate( &vkey, NULL, "ca.crt" ));

  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
