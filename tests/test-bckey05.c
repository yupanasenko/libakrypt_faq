/* Тестовый пример иллюстрирует применение режима простой замены с зацеплением (Магма).
   Внимание! Используются не экспортируемые функции.

   test-bckey05.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_bckey.h>
 #include <ak_tools.h>

 int main()
{
  int result = EXIT_FAILURE;

 /* устанавливаем флаг совместимости с openssl: 0 - нет совместимости, 1 - есть */
  int i, j;
  ak_uint8 buf[128], *ptr;
  struct bckey bkey;

 /* значение секретного ключа согласно ГОСТ Р 34.12-2015 */
  ak_uint8 key[32] = {
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

 /* открытый текст из ГОСТ Р 34.12-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint8 in[32] = {
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
    0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
    0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
    0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
  };

 /* инициализационный вектор для режима гаммирования (счетчика) */
  ak_uint8 ivcbc[24] = {
    0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
    0xf1, 0xde, 0xbc, 0x0a, 0x89, 0x67, 0x45, 0x23,
    0x12, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34
  };

 /* зашифрованный блок из ГОСТ Р 34.12-2015 */
  ak_uint8 outcbc[32] = {
    0x19, 0x39, 0x68, 0xea, 0x5e, 0xb0, 0xd1, 0x96,
    0xb9, 0x37, 0xb9, 0xab, 0x29, 0x61, 0xf7, 0xaf,
    0x19, 0x00, 0xbc, 0xc4, 0xa1, 0xb4, 0x58, 0x50,
    0x67, 0xe6, 0xd7, 0x7c, 0x1a, 0x8b, 0xb7, 0x20
  };


 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* устанавливаем нужный вариант совместимости и пересчитываем внутренние таблицы */
  ak_libakrypt_set_option( "openssl_compability", 0);

 /* создаем секретный ключ алгоритма Кузнечик */
  if( ak_bckey_context_create_magma( &bkey ) != ak_error_ok )
    return ak_libakrypt_destroy();

 /* устанавливаем секретный ключ */
  ak_bckey_context_set_key( &bkey, key, sizeof( key ));

 /* зашифровываем */
  ak_bckey_context_encrypt_cbc( &bkey, in, buf, sizeof( in ), ivcbc, sizeof(ivcbc) );
  printf("encrypted:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 8; j++ ) printf(" %02x", buf[i*8+j] );
    printf("\n");
  }

  ptr = outcbc;
  printf("\nexpected:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 8; j++ ) printf(" %02x", ptr[i*8+j] );
    printf("\n");
  }

  if( ak_ptr_is_equal( buf, ptr, 32 )) {
    printf("Ok\n\n");
    result = EXIT_SUCCESS;
  }  else printf("Wrong\n\n");

  ak_bckey_context_decrypt_cbc( &bkey, outcbc, buf, sizeof( outcbc ), ivcbc, sizeof(ivcbc) );
  printf("decrypted:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 8; j++ ) printf(" %02x", buf[i*8+j] );
    printf("\n");
  }

  ptr = in;
  printf("\nexpected:\n");
  for( i = 0; i < 4; i++ ) {
    for( j = 0; j < 8; j++ ) printf(" %02x", ptr[i*8+j] );
    printf("\n");
  }

  if( ak_ptr_is_equal( buf, ptr, 32 )) {
    printf("Ok\n");
    result = EXIT_SUCCESS;
  }  else printf("Wrong\n");

  ak_bckey_context_destroy( &bkey );
  ak_libakrypt_destroy();

 return result;
}
