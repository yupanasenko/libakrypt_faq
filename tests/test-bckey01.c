/* Тестовый пример иллюстрирует операции зашифрования/расшифрования одного блока
   информации, а также программную возможность выбирать способ
   соместимости с преобразованиями, реализуемыми библиотекой openssl.
   Внимание! Используются не экспортируемые функции.

   test-bckey01.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_bckey.h>
 #include <ak_tools.h>

/*
   инвертированные тестовые значения взяты из
   https://github.com/gost-engine/engine/blob/master/test_grasshopper.c

   запуск
     test-bckey01 проводит тестирование для оригинальной реализации
     test-bckey01 1 проводит тестирование для реализации, совместимой с openssl */

 int main( int argc, char *argv[] )
{
 /* устанавливаем флаг совместимости с openssl: 0 - нет совместимости, 1 - есть */
  int oc = 0;
  ak_uint8 buf[16];
  struct bckey bkey,  /* это контекст ключа для алгоритма Кузнечик */
               mkey;  /* это контекст ключа для алгоритма Магма */

 /* значение секретного ключа согласно ГОСТ Р 34.12-2015 для алгоритма Кузнечик, приложение А.1 */
  ak_uint8 key[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 /* тот же ключ, но в инвертированном виде */
  ak_uint8 openssl_key[32] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

 /* значение секретного ключа согласно ГОСТ Р 34.12-2015 для алгоритма Магма, приложение А.2 */
  ak_uint8 key_magma[32] = {
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

 /* тот же ключ, но в инвертированном виде */
  ak_uint8 openssl_key_magma[32] = {
     0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  };

 /* открытый текст из ГОСТ Р 34.12-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint8 in[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
  ak_uint8 openssl_in[16] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88 };

 /* подлежащий зашифрованию открытый текст из ГОСТ Р 34.12-2015, приложение А.2 */
  ak_uint8 in_magma[8] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe };
  ak_uint8 openssl_in_magma[8] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

 /* зашифрованный блок из ГОСТ Р 34.12-2015 */
  ak_uint8 out[16] = {
    0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a, 0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f };

  ak_uint8 openssl_out[] = {
    0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd };

 /* зашифрованный блок из ГОСТ Р 34.12-2015, приложение А.2 */
  ak_uint8 out_magma[8] = { 0x3d, 0xca, 0xd8, 0xc2, 0xe5, 0x01, 0xe9, 0x4e };
  ak_uint8 openssl_out_magma[8] = { 0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d };

 /* передаем в программу значение флага совместимости */
  if( argc > 1 ) oc = atoi( argv[1] );
  if( oc != 1 ) oc = 0;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* устанавливаем нужный вариант совместимости и пересчитываем внутренние таблицы */
  ak_libakrypt_set_option( "openssl_compability", oc );
  ak_bckey_context_kuznechik_init_gost_tables();

 /* создаем секретный ключ алгоритма Кузнечик */
  if( ak_bckey_context_create_kuznechik( &bkey ) != ak_error_ok )
    return ak_libakrypt_destroy();

 /* создаем секретный ключ алгоритма Кузнечик */
  if( ak_bckey_context_create_magma( &mkey ) != ak_error_ok )
    return ak_libakrypt_destroy();

 /* устанавливаем секретный ключ */
  ak_bckey_context_set_key( &bkey, oc ? openssl_key : key, sizeof( key ));
  ak_bckey_context_set_key( &mkey, oc ? openssl_key_magma : key_magma, sizeof( key_magma ));

 /* алгоритм Кузнечик */
  printf("kuznechik\n");

 /* зашифровываем и расшифровываем всего блок данных в режиме простой замены */
  bkey.encrypt( &bkey.key, oc ? openssl_in : in, buf );
  printf("encrypted: %s\n", ak_ptr_to_hexstr( buf, 16, ak_false ));
  printf(" expected: %s\n", ak_ptr_to_hexstr( oc ? openssl_out : out, 16, ak_false ));

  bkey.decrypt( &bkey.key, oc ? openssl_out : out, buf );
  printf("decrypted: %s\n", ak_ptr_to_hexstr( buf, 16, ak_false ));
  printf(" expected: %s\n", ak_ptr_to_hexstr( oc ? openssl_in : in, 16, ak_false ));

 /* алгоритм Магма */
  printf("\nmagma\n");

 /* зашифровываем и расшифровываем всего блок данных в режиме простой замены */
  mkey.encrypt( &mkey.key, oc ? openssl_in_magma : in_magma, buf );
  printf("encrypted: %s\n", ak_ptr_to_hexstr( buf, 8, ak_false ));
  printf(" expected: %s\n", ak_ptr_to_hexstr( oc ? openssl_out_magma : out_magma, 8, ak_false ));

  mkey.decrypt( &mkey.key, oc ? openssl_out_magma : out_magma, buf );
  printf("decrypted: %s\n", ak_ptr_to_hexstr( buf, 8, ak_false ));
  printf(" expected: %s\n", ak_ptr_to_hexstr( oc ? openssl_in_magma : in_magma, 8, ak_false ));

 /* уничтожаем ключи */
  ak_bckey_context_destroy( &bkey );
  ak_bckey_context_destroy( &mkey );

 return ak_libakrypt_destroy();
}
