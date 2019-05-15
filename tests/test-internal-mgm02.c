/* Тестовый пример, иллюстрирующий работу только с контекстом алгоритма выработки имитовставки MGM.
   Тестирование процедур шифрования/расшифрования данных не выполняется.

   Пример использует неэкспортируемые функции.

   test-internal-mgm02.c
*/


 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ak_mgm.h>

/* общая тестурующая функция */
 int common_test_function( ak_mgm );

/* общие данные */
 static ak_uint8 out[16], out1[16]; /* значение имитовставки */
 static  ak_uint8 testkey[32] = { /* тестовое значение ключа */
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x87 };

 static  ak_uint8 testiv[16] = { /* инициализионный вектор (синхропосылка) */
     0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0xa1, 0xb2, 0xc3, 0xd4, 0x15, 0x26, 0x37, 0x48 };
 static ak_uint8 testdata[4] = { 0x00, 0x11, 0xff, 0x12 }; /* данные */

 int main( void )
{
  struct mgm mctx;  /* внутренняя структура алгоритма выработки имитовставки */

  ak_libakrypt_create( ak_function_log_stderr );
  if( !ak_libakrypt_dynamic_control_test()) return ak_libakrypt_destroy();

 /* тестируем Mагму */
  printf("create [magma]: %d\n", /* создаем контекст алгоритма выработки имитовставки */
                                 ak_mgm_context_create_magma( &mctx ));
  if( common_test_function( &mctx ) != EXIT_SUCCESS ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* тестируем Кузнечик */
  printf("create [Kuznechik]: %d\n", ak_mgm_context_create_kuznechik( &mctx ));
  if( common_test_function( &mctx ) != EXIT_SUCCESS ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 return ak_libakrypt_destroy();
}

 int common_test_function( ak_mgm mctx )
{
  size_t i;
  printf("algorithm: %s\n", mctx->bkey.key.oid->name );
 /* устанавливаем секретный ключ */
  printf("set key: %d\n", ak_mgm_context_set_key( mctx, testkey, sizeof( testkey ), ak_true ));
 /* устанавливаем инициализационный вектор */
  printf("set iv: %d\n", ak_mgm_context_set_iv( mctx, testiv, mctx->bkey.bsize ));
                                            /* длина инициализационного вектора
                                               совпадает с длиной блока алгоритма шифрования */
  printf("clean: %d\n", ak_mgm_context_clean( mctx ));
  ak_mgm_context_finalize( mctx, testdata, sizeof( testdata ), out );
  printf("finalize: %d\n", ak_error_get_value());

  printf("out: ");
  for( i = 0; i < mctx->bkey.bsize; i++ ) printf("%02X ", out[i]);
  printf(" [%u octets]\n", ( unsigned int ) mctx->bkey.bsize );

 /* проверяем результат */
  ak_bckey_context_encrypt_mgm( NULL, &mctx->bkey,  /* ключи */
                                testdata, sizeof( testdata ), /* ассоциированные данные */
                                NULL, NULL, 0,  /* зашифровываемые данные */
                                testiv, mctx->bkey.bsize, /* инициализационный вектор */
                                out1, mctx->bkey.bsize  /* имитовставка */
                              );
  printf("new: ");
  for( i = 0; i < mctx->bkey.bsize; i++ ) printf("%02X ", out[i]);
  printf(" [%u octets]\n", (unsigned int) mctx->bkey.bsize );
  printf("destroy: %d\n", ak_mgm_context_destroy( mctx ));

  if( memcmp( out, out1, mctx->bkey.bsize ) != 0 ) return EXIT_FAILURE;
 return EXIT_SUCCESS;
}
