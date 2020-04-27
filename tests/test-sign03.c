/* Пример иллюстрирует применение неэкспортируемых функций для создания
   запросов на сертификат.
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <time.h>

 #include <ak_sign.h>
 #include <ak_asn1_keys.h>

 int main( int argc, char *argv[] )
{
  int ecode = EXIT_SUCCESS;
  char *skeyname = "secret.key";
  char *vkeyname = "public.key";
  struct signkey sk;
  struct verifykey vk;
  ak_oid oid = NULL;
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };

  ak_libakrypt_create( ak_function_log_stderr );

 /* 1. Создаем секретный ключ */
  oid = ak_oid_context_find_by_id( "1.2.643.7.1.2.1.1.1" );
  if( ak_signkey_context_create_streebog256_with_curve( &sk, (ak_wcurve)oid->data ) != ak_error_ok ) {
    ecode = EXIT_FAILURE;
    goto exlab;
  }

 /* устанавливаем значение ключа */
  ak_signkey_context_set_key( &sk, testkey, sizeof( testkey ));
 /* подстраиваем ключ и устанавливаем ресурс */
  ak_skey_context_set_resource_values( &sk.key, key_using_resource,
               "digital_signature_count_resource", 0, time(NULL)+2592000 ); /* 1 месяц */
 /* вырабатываем открытый ключ */
  ak_verifykey_context_create_from_signkey( &vk, &sk );

 /* сохраняем секретный ключ*/
  ak_key_context_export_to_file_with_password(
    &sk,                  /* контекст секретного ключа */
    sign_function, /* тип криптографического механизма */
    "12345678",                              /* пароль */
    8,                   /* количество символов пароля */
    "test secret key",   /* человекочитаемое имя ключа */
    skeyname,             /* файл для сохранения ключа */
    0,  /* ноль, поскольку имя файла получать не нужно */
    asn1_pem_format           /* формат хранения ключа */
  );

 /* 2. Создаем запрос на создание сертификата открытого ключа */
  ak_verify_context_set_name_string( &vk, "CountryName", "RU" );
  ak_verify_context_set_name_string( &vk, "LocalityName", "Санкт-Петербург" );
  ak_verify_context_set_name_string( &vk, "StateOrProvinceName", "78 г. Санкт-Петербург" );
  ak_verify_context_set_name_string( &vk, "emailAddress", "some@mail.address" );
  ak_verify_context_set_name_string( &vk, "CommonName", "Example" );

 /* 3. Сохраняем запрос */
  ak_verifykey_context_export_to_request(
    &vk,  /* контекст открытого ключа -- значение сохраняем в запрос */
    &sk,  /* контекст секретного ключа -- используем для выработки подписи */
    vkeyname, /* имя файла */
    asn1_der_format /* формат хранения der/pem */
  );

 /* уничтожаем открытый ключ */
  ak_verifykey_context_destroy( &vk );
 /* уничтожаем секретный ключ */
  ak_signkey_context_destroy( &sk );

  exlab: ak_libakrypt_destroy();
 return ecode;
}
