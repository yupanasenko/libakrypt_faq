/* Пример показывает простейшую процедуру электроной подписи
   и иллюстрирует множество внутренних состояний секретного ключа.
   Внимание! Используются неэкспортируемые функции.

   test-sign01.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_oid.h>
 #include <ak_skey.h>
 #include <ak_sign.h>
 #include <ak_asn1_keys.h>
 #include <ak_parameters.h>

 int main( int argc, char *argv[] )
{
  ak_oid oid = NULL;
  struct signkey sk;
  struct verifykey pk;
  int result = EXIT_SUCCESS;
  ak_uint8 sign[128];
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* инициализируем секретный ключ */
  oid = ak_oid_context_find_by_name( "cspa" );
  if(( ak_signkey_context_create( &sk, (ak_wcurve) oid->data )) != ak_error_ok ) {
    result = EXIT_FAILURE;
    goto exlab;
  }
 /* устанавливаем значение ключа */
  ak_signkey_context_set_key( &sk, testkey, 32 );
 /* подстраиваем ключ и устанавливаем ресурс */
  ak_skey_context_set_resource_values( &sk.key, key_using_resource,
               "digital_signature_count_resource", 0, time(NULL)+2592000 );
 /* выводим значение ключа для информации */
  ak_skey_context_print_to_file( &sk.key, stdout );
 /* только теперь подписываем данные
    в качестве которых выступает исполняемый файл */
  ak_signkey_context_sign_file( &sk, argv[0], sign, sizeof( sign ));
  printf("file:   %s\nsign:   %s\n", argv[0],
     ak_ptr_to_hexstr( sign, ak_signkey_context_get_tag_size(&sk), ak_false ));

 /* формируем открытый ключ */
  ak_verifykey_context_create_from_signkey( &pk, &sk );
 /* проверяем подпись */
  if( ak_verifykey_context_verify_file( &pk, argv[0], sign ) == ak_true )
    printf("verify: Ok\n");
   else { printf("verify: Wrong\n"); result = EXIT_FAILURE; }

  ak_signkey_context_destroy( &sk );
  ak_verifykey_context_destroy( &pk );

  exlab: ak_libakrypt_destroy();
 return result;
}
