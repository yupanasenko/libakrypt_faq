/* ----------------------------------------------------------------------------------------------- *
   Тестовый пример, иллюстрирующий генерацию секретных ключей из пароля
   (обработку длинных паролей)

   Внимание: используются неэкспортируемые функции библиотеки
 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <ak_hmac.h>

 int main( void )
{
  struct hmac hx;
  struct hash ctx;
  char *pass = "yuoiasdkfk32qahjdhsbsajdbdkфыяяфы12oojskjasdkabcbkcabdkadhgkdgfkahbckbakjb3762827qqqwwquyew879875743974kdjbfbksdjbcskcbskdjcbsdckjsbdcksjdbcsdcb";
  char *salt = "salt";
  ak_uint8 out[64], out2[64],
           data[13] = { 0x0a, 0xb, 0xc, 0xd, 0xe, 0xf, 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0xa2 };
  char string[512];

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

  printf("we have a long password: \n%s (%d bytes)\n", pass, (int)strlen( pass));

 /* инициализируем контекст длинным паролем */
   ak_hmac_context_create_streebog256( &hx );
   ak_hmac_context_set_key_from_password( &hx, pass, strlen(pass), salt, strlen(salt));
 /* вычисляем имитовставку от константы */
   ak_hmac_context_ptr( &hx, data, sizeof( data ), out );
   ak_ptr_to_hexstr_static( out, 32, string, 512, ak_false );
   printf("hmac: %s\n\n", string );
   ak_hmac_context_destroy( &hx );

 /* теперь хешируем пароль в лоб */
   ak_hash_context_create_streebog512( &ctx );
   ak_hash_context_ptr( &ctx, pass, strlen(pass), out2 );
   ak_ptr_to_hexstr_static( out2, 64, string, 512, ak_false );
   printf("hash: %s\n", string );
   ak_hash_context_destroy( &ctx );

 /* инициализируем контекст вычисленным хеш-кодом от пароля */
   ak_hmac_context_create_streebog256( &hx );
   ak_hmac_context_set_key_from_password( &hx, out2, 64, salt, strlen(salt));

 /* и снова вычисляем имитовставку от константы */
   ak_hmac_context_ptr( &hx, data, sizeof( data ), out2 );
   ak_ptr_to_hexstr_static( out2, 32, string, 512, ak_false );
   printf("hmac: %s\n\n", string );
   ak_hmac_context_destroy( &hx );

 /* останавливаем библиотеку и возвращаем результат сравнения */
   ak_libakrypt_destroy();

 return memcmp( out, out2, 32 );
}
