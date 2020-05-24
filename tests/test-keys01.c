 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_skey.h>
 #include <ak_key_manager.h>

 int main( void )
{
  struct key_manager km;

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();


  printf("create: %d\n", ak_key_manager_create_directory( &km, NULL ));
  ak_key_manager_destroy( &km );


 return EXIT_SUCCESS;
}
