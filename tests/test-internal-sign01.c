/* Пример, иллюстрирующий базовые процедуры выработки и проверки электронной подписи
   Внимание! Используются неэкспортируемые функции.

   test-internal-sign01.c */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_sign.h>
 #include <ak_parameters.h>

 int main( void )
{
  struct signkey skey; /* секретный ключ подписи */
  struct verifykey vkey; /* открытый ключ подписи */
  int error = ak_error_ok;
  ak_uint8 buffer[128]; /* буффер для хранения электронной подписи */
  char str[512]; /* буффер для символьного вывода */

  ak_uint8 key256[32] = { /* константное значение секретного ключа */
   0x28, 0x3B, 0xEC, 0x91, 0x98, 0xCE, 0x19, 0x1D, 0xEE, 0x7E, 0x39, 0x49, 0x1F, 0x96, 0x60, 0x1B,
   0xC1, 0x72, 0x9A, 0xD3, 0x9D, 0x35, 0xED, 0x10, 0xBE, 0xB9, 0x9B, 0x78, 0xDE, 0x9A, 0x92, 0x7A };

 /* константное значение открытого ключа */
  ak_uint8 openkey[64] = {
   0xE4, 0x72, 0xDF, 0xD0, 0x09, 0x5B, 0x29, 0x32, 0xB2, 0x14, 0xF8, 0xDF, 0x8B, 0xF4, 0xFF, 0x64,
   0xEE, 0x0B, 0x04, 0xE9, 0x18, 0xD2, 0xF3, 0x54, 0xC1, 0x84, 0xDC, 0xB0, 0x1A, 0xC2, 0x21, 0xFD,
   0x49, 0x50, 0xE4, 0x58, 0x14, 0x1D, 0x04, 0x86, 0xDF, 0x62, 0x58, 0xA9, 0x82, 0x9A, 0x23, 0x59,
   0x06, 0x7E, 0x30, 0xA2, 0xD7, 0x01, 0x2A, 0x1A, 0x06, 0x07, 0x4F, 0xAC, 0xC9, 0xDE, 0x26, 0x50 };

 /* инициализация библиотеки
    (NULL означает, что все сообщения об ошибках будут выводиться в /var/log/auth.log */
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* инициализируем контекст секретного ключа и устанавливаем эллиптическую кривую */
  if(( error = ak_signkey_context_create_streebog256(
                   &skey, (const ak_wcurve) &id_rfc4357_gost_3410_2001_paramSetA )) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка при конструировании секретного ключа" );
    return ak_libakrypt_destroy();
  }

 /* создаем секретный ключ ЭП */
  if(( error = ak_signkey_context_set_key( &skey, key256, sizeof( key256 ), ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка при инициализации секретного ключа" );
    ak_signkey_context_destroy( &skey );
    return ak_libakrypt_destroy();
  }

 /* вычисляем подпись под заданным вектором */
  ak_signkey_context_sign_ptr( &skey, "1234567890", 10, buffer );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка при вычислении электронной подписи" );
    ak_signkey_context_destroy( &skey );
    return ak_libakrypt_destroy();
  }

 /* выводим полученное значение электронной подписи в консоль */
  ak_ptr_to_hexstr_static( buffer, 2*skey.ctx.hsize, str, sizeof( str ), ak_false );
  printf("sign: %s\n", str );

 /* теперь вырабатываем открытый ключ */
  if(( error = ak_verifykey_context_create_from_signkey( &vkey, &skey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка при конструировании открытого ключа" );
    ak_signkey_context_destroy( &skey );
    return ak_libakrypt_destroy();
  }

 /* теперь проверка выработанной подписи */
  if( ak_verifykey_context_verify_ptr( &vkey, "1234567890", 10, buffer )) printf("sign Ok\n");
    else printf("sign Wrong\n");

 /* тестируем экспорт: выводим значение открытого ключа в консоль */
  if(( error = ak_verify_context_export_ptr( &vkey, buffer, sizeof( buffer ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка при экспорте открытого ключа" );
    goto lab_exit;
  }
  ak_ptr_to_hexstr_static( buffer, sizeof( openkey ), str, sizeof( str ), ak_false );
  printf("openkey: %s ", str );
  if( ak_ptr_is_equal( openkey, buffer, sizeof( openkey ))) printf("Ok\n");
    else printf("Wrong\n");

 /* уничтожаем созданные ключи */
  lab_exit:
  ak_signkey_context_destroy( &skey );
  ak_verifykey_context_destroy( &vkey );

 /* завершаем работу с библиотекой */
 return ak_libakrypt_destroy();
}
