 #include <stdio.h>
 #include <libakrypt.h>
 #include <ak_skey.h>
 #include <ak_hash.h>
 #include <ak_tools.h>

 int main( void )
{
  char password[32], *str = NULL;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
   return ak_libakrypt_destroy();
  }

  do{
      printf("password: ");
  } while( ak_password_read( password, 32 ) != ak_error_ok );

  printf("\ninput value: %s (len: %llu, hex: %s)\n",
                   password, (unsigned long long) strlen(password),
                                 str = ak_ptr_to_hexstr( password, 32, ak_false ));
  free(str);

 return ak_libakrypt_destroy();
}
