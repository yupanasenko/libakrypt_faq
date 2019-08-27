/* Пример, иллюстрирующий вычисление хеша от пароля.
   Внимание! Используются неэкспортируемые функции.

   test-internal-hash03.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_hash.h>

 int main( void )
{
  ak_uint8 out[32];  /* значение хеш-функции */
  struct hash ctx;
  int i = 0, res = EXIT_SUCCESS;

 /* проверочная константа */
  ak_uint8 sout[32] = {
   0xC6, 0x00, 0xFD, 0x9D, 0xD0, 0x49, 0xCF, 0x8A, 0xBD, 0x2F, 0x5B, 0x32, 0xE8, 0x40, 0xD2, 0xCB,
   0x0E, 0x41, 0xEA, 0x44, 0xDE, 0x1C, 0x15, 0x5D, 0xCD, 0x88, 0xDC, 0x84, 0xFE, 0x58, 0xA8, 0x55 };

 /* инициализация библиотеки
    (NULL означает, что все сообщения об ошибках будут выводиться в /var/log/auth.log */
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* вычисление хеша для фиксированного пароля */
  ak_hash_context_create_streebog256( &ctx );
  ak_hash_context_ptr( &ctx, "hello world", 11, out );
  ak_hash_context_destroy( &ctx );

 /* сверяем значение хеша с константой */
  printf("hash: ");
  for( i = 0; i < 32; i++ ) {
     printf("%02X", out[i] );
     if( out[i] != sout[i] ) res = EXIT_FAILURE;
  }
  if( res == EXIT_SUCCESS ) printf(" Ok\n"); else printf(" No\n");

 /* завершаем работу с библиотекой */
  ak_libakrypt_destroy();

 return res;
}
