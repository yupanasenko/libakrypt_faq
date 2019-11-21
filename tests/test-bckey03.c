/* Тестовый пример иллюстрирует операции зашифрования/расшифрования одного блока
   информации, а также программную возможность выбирать способ
   совместимости с преобразованиями, реализуемыми библиотекой openssl.
   Внимание! Используются не экспортируемые функции.

   test-bckey03.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_bckey.h>
 #include <ak_tools.h>


 int main( int argc, char *argv[] )
{
  int oc = 0;
  ak_uint8 buf[8];
  struct bckey bkey;

  ak_uint8 gost3412_2015_key[32] = { /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.2 */
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  ak_uint8 oc_key[32] = {
     0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  };

 /* подлежащий зашифрованию открытый текст из ГОСТ Р 34.12-2015, приложение А.2 */
  ak_uint8 a[8] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe };
  ak_uint8 oc_a[8] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

 /* зашифрованный текст из ГОСТ Р 34.12-2015 */
  ak_uint8 b[8] = { 0x3d, 0xca, 0xd8, 0xc2, 0xe5, 0x01, 0xe9, 0x4e };
  ak_uint8 oc_b[8] = { 0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d };

 /* передаем в программу значение флага совместимости */
  if( argc > 1 ) oc = atoi( argv[1] );
  if( oc != 1 ) oc = 0;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* устанавливаем нужный вариант совместимости и пересчитываем внутренние таблицы */
  ak_libakrypt_set_option( "openssl_compability", oc );

 /* создаем секретный ключ алгоритма Кузнечик */
  if( ak_bckey_context_create_magma( &bkey ) != ak_error_ok )
    return ak_libakrypt_destroy();

 /* устанавливаем секретный ключ */
  ak_bckey_context_set_key( &bkey, oc ? oc_key : gost3412_2015_key, 32 );

 /* зашифровываем и расшифровываем всего блок данных в режиме простой замены */
  ak_bckey_context_encrypt_ecb( &bkey, oc ? oc_a : a, buf, 8 );
  printf("encrypted: %s\n", ak_ptr_to_hexstr( buf, 8, ak_false ));
  printf(" expected: %s\n", ak_ptr_to_hexstr( oc ? oc_b : b, 8, ak_false ));

//  ak_bckey_context_decrypt_ecb( &bkey, buf, buf, 8 );
//  printf("decrypted: %s\n", ak_ptr_to_hexstr( buf, 8, ak_false ));
//  printf(" expected: %s\n", ak_ptr_to_hexstr( a, 8, ak_false ));

  ak_bckey_context_destroy( &bkey );
 return ak_libakrypt_destroy();
}
