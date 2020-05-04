/* Пример иллюстрирует применение неэкспортируемых функций для создания
   запросов на сертификат.
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>

 #include <ak_sign.h>
 #include <ak_asn1_keys.h>

 int get_user_password( char * , size_t );

 int main( void )
{
  int ecode = EXIT_SUCCESS;
  char *skeyname = "secret.key";
  char *vkeyname = "public.key";
  char *keyname = NULL;
  struct signkey sk;
  struct verifykey vk;
  ak_oid oid = NULL;
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };
  ak_uint8 sign[128];

  ak_libakrypt_create( ak_function_log_stderr );

 /* создаем секретный ключ */
  oid = ak_oid_context_find_by_ni( "id-tc26-gost-3410-2012-256-paramSetTest" ); // "1.2.643.7.1.2.1.1.1" );
  if( ak_signkey_context_create_streebog256_with_curve( &sk, (ak_wcurve)oid->data ) != ak_error_ok ) {
    ecode = EXIT_FAILURE;
    goto exlab;
  }

 /* устанавливаем значение ключа */
  ak_signkey_context_set_key( &sk, testkey, sizeof( testkey ));

 /* подстраиваем ключ и устанавливаем ресурс */
  ak_skey_context_set_resource_values( &sk.key, key_using_resource,
               "digital_signature_count_resource", time(NULL), time(NULL)+2592000 ); /* 1 месяц */
 /* подписываем данные */
  if( ak_signkey_context_sign_ptr( &sk, testkey,
                                         sizeof( testkey ), sign, sizeof( sign )) != ak_error_ok )
    printf("incorrect creation of digital signature\n");
   else printf( " signature %s\n",
                       ak_ptr_to_hexstr( sign, ak_signkey_context_get_tag_size( &sk ), ak_false ));

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
    asn1_der_format           /* формат хранения ключа */
  );

 /* создаем последовательность обобщенных имен для владельца ключа */
  ak_verifykey_context_set_name_string( &vk, "CountryName", "RU" );
  ak_verifykey_context_set_name_string( &vk, "LocalityName", "Большое Свинорье" );
  ak_verifykey_context_set_name_string( &vk, "StateOrProvinceName", "Московская область" );
  ak_verifykey_context_set_name_string( &vk, "emailAddress", "some@mail.address" );
  ak_verifykey_context_set_name_string( &vk, "CommonName", "Example" );

 /* сохраняем запрос */
  ak_verifykey_context_export_to_request(
    &vk,       /* контекст открытого ключа -- значение сохраняем в запрос */
    &sk, /* контекст секретного ключа -- используем для выработки подписи */
    vkeyname,                                                /* имя файла */
    0,                     /* ноль, поскольку имя файла получать не нужно */
    asn1_der_format                            /* формат хранения der/pem */
  );

 /* уничтожаем открытый ключ */
  ak_verifykey_context_destroy( &vk );
 /* уничтожаем секретный ключ */
  ak_signkey_context_destroy( &sk );

 /* выполняем проверку процедуры чтения ключа и проверки подписи */
  ak_verifykey_context_import_from_request( &vk, vkeyname );
  if( ak_verifykey_context_verify_ptr( &vk, testkey, sizeof( testkey ), sign )) {
    ecode = EXIT_SUCCESS;
    printf(" is Ok\n");
  }
    else {
      ecode = EXIT_FAILURE;
      goto exlac;
    }

 /* теперь создаем сертификат ключа
    поскольку у нас только одна пара ключей, то сертификат будет самоподписанным */

 /* начинаем с того, что определяем функцию чтения пароля
    это позволит не вводить пароль с консоли */
  ak_libakrypt_set_password_read_function( get_user_password );

 /* считываем из контейнера ключ подписи сертификата */
  ak_signkey_context_import_from_file( &sk, skeyname, &keyname );
  if( keyname ) printf("loaded secret key: %s\n", keyname );

 /* указываем имя лица, заверяющего сертификат, фактически это имя УЦ */
  sk.name = ak_tlv_context_duplicate_global_name( vk.name );

 /* вырабатываем сертикафикат */
  ak_verifykey_context_export_to_certificate(
    &vk,  /* контекст открытого ключа -- значение помещается в сертификат */
    &sk, /* контекст секретного ключа -- используем для выработки подписи */
    "first.crt",        /* имя файла, в который будет сохранен сертификат */
    0,                       /* размер доступного буффера для имени файла */
    asn1_pem_format          /* формат хранения сертификата - der или pem */
  );

  ak_signkey_context_destroy( &sk );
  if( keyname ) free( keyname );

  exlac: ak_verifykey_context_destroy( &vk );
  exlab: ak_libakrypt_destroy();
 return ecode;
}

/* ----------------------------------------------------------------------------------------------- */
/* определяем функцию, которая будет имитировать чтение пароля пользователя */
 int get_user_password( char *password, size_t psize )
{
  memset( password, 0, psize );
  ak_snprintf( password, psize, "12345678" );
 return ak_error_ok;
}
