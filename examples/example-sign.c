 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 ak_handle secretkey, publickey;
 char password[64], *str = NULL,
      data[27] = "1234567890abcdefzzaapo9-091";
 ak_buffer result = NULL;

  if( !ak_libakrypt_create( ak_function_log_stderr ))
    ak_libakrypt_destroy();

 /* создаем ключ */
  if(( secretkey = ak_signkey_new_streebog256(
    ak_oid_find_by_name( "id-tc26-gost3410-2012-256-paramsetA" ),
                "my secret DS key" )) == ak_error_wrong_handle ) {
    printf("wrong secret key creation\n");
    return ak_libakrypt_destroy();
  }

 /* присваиваем ключу значение */
  printf("password: "); fflush( stdout );
  ak_password_read( password, 64 );
  printf("\n");
  if( ak_signkey_set_key_password( secretkey,
              password, strlen(password), "1234", 4 ) != ak_error_ok ) {
    printf("wrong secret key initialization\n");
    return ak_libakrypt_destroy();
  }

 /* вырабатываем подпись */
  result = ak_signkey_ptr( secretkey, data, 27, NULL );
  if( result == NULL ) {
    printf("wrong digital signature calculation\n");
    return ak_libakrypt_destroy();
  }
  printf("size of sign [real: %d, estimated: %d]\n",
   (int) ak_buffer_get_size( result ), (int) ak_signkey_get_icode_size( secretkey ));
  printf("%s\n", str = ak_buffer_to_hexstr( result )); free( str );

 /* вычисляем открытый ключ из пароля */
  if(( publickey = ak_verifykey_new_signkey( secretkey,
               "my public DS key" )) == ak_error_wrong_handle ) {
    printf("wrong public key creation\n");
    return ak_libakrypt_destroy();
  }

 /* проверяем подпись */
  if( ak_verifykey_ptr( publickey, data, 27, ak_buffer_get_ptr( result )))
    printf("Sign is Ok\n");
   else printf("Sign is Wrong\n");

  ak_buffer_delete( result );
 return ak_libakrypt_destroy();
}
