 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
  char *str = NULL;
  ak_key key = ak_error_wrong_key;
  int error = ak_error_ok;
  ak_buffer password = NULL;
  ak_uint8 iv[4] = { 0, 1, 2, 3 },
           enc_data[53],
           plain_data[53] = "abcdefgh000132432123456aaascdfszswqkndbbdknanbdbbbbs1";

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* вводим пароль */
  password = ak_buffer_new_size( 128 );
  printf("password: ");
  if(( error = ak_password_read_buffer( password )) != ak_error_ok ) goto ext;
  printf("\ninput value: %s\n", ak_buffer_get_ptr( password ));

 /* создаем ключ */
  key = ak_key_new_magma_password( password, NULL );
  printf("key: %ld\nplain text: %s\n", key,
              str = ak_ptr_to_hexstr( plain_data, sizeof( plain_data ), ak_false )); free(str);

 /* зашифровываем данные */
  ak_key_xcrypt_ctr( key, plain_data, enc_data, sizeof(plain_data), iv );
  printf("encrypt   : %s\n",
              str = ak_ptr_to_hexstr( enc_data, sizeof( enc_data ), ak_false )); free(str);

  ak_key_xcrypt_ctr( key, enc_data, enc_data, sizeof(enc_data), iv );
  printf("plain_text: %s ",
              str = ak_ptr_to_hexstr( enc_data, sizeof( enc_data ), ak_false )); free(str);
  if( memcmp( plain_data, enc_data, sizeof( enc_data )) == 0 ) printf("Ok\n");
    else printf(" Wrong\n");

  ext: password = ak_buffer_delete( password );
 return ak_libakrypt_destroy();
}


