/* пример иллюстрирует процесс выработки кода целостности или имитовставки
   от заданной области памяти. используется общий механизм класса mac. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libakrypt.h>

/* список имен алгоритмов, которые реализуют вычисление кода целостности */
 static const char *algorithms[] = {
  "streebog256",
  "streebog512",
  "hmac-streebog256",
  "hmac-streebog512",
  "omac-magma",
  "omac-kuznechik",
  "mgm-magma",
  "mgm-kuznechik",
  NULL
 };

/* данные, для которых вычисляется код целостности */
 static ak_uint8 data[10] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a };

/* данные, используемые для генерации пароля */
 static ak_uint8 salt[4] = { 0xab, 0xcd, 0xef, 0x01 };

/* данные, представляющие собой пароль */
 static ak_uint8 password[11] = "x3Ea-A1zcQp";

/* данные, представляющие собой синхропосылку */
 static ak_uint8 iv[16] = {
  0xaf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaf };

 int main( void )
{
  oid_modes_t mode;
  oid_engines_t engine;
  ak_buffer buffer = NULL;
  int idx = 0, error = ak_error_ok;
  ak_handle handle = ak_error_wrong_handle;
  char algorithmName[128], algorithmOID[128];

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }
 /* проверяем, что у нас достаточно памяти для имен и идентификаторов алгоритмов
    данные значения нужны нам только для иллюстрации работы */
  if( sizeof( algorithmName ) < ak_libakrypt_get_oid_max_length() ) {
     ak_error_message( ak_error_get_value(), __func__, "not sufficient memory for algorithms names" );
     goto exit;
  }

 /* перебираем все допустимые имена алгоритмов */
  while( algorithms[idx] != NULL ) {

     /* создаем дескриптор алгоритма */
      if(( handle = ak_mac_new_oid( algorithms[idx], NULL )) == ak_error_wrong_handle ) {
        ak_error_message( ak_error_get_value(), __func__, "incorrect creation mac handle" );
        continue;
      }

     /* получаем информацию о созданном алгоритме */
      if(( error = ak_libakrypt_get_oid_by_handle( handle, &engine, &mode,
        algorithmName, sizeof( algorithmName ), algorithmOID,
                                                        sizeof( algorithmOID ))) != ak_error_ok ) {
        ak_error_message( ak_error_get_value(), __func__, "incorrect getting the OID information" );
        goto exit_local;
      }
      printf("%s [engine: %s, mode: %s, OID: %s]\n", algorithmName,
             ak_libakrypt_get_engine_name( engine ), ak_libakrypt_get_mode_name( mode ), algorithmOID );

     /* проверяем, что алгоритм допускает использование ключа */
      if( ak_mac_is_key_settable( handle )) {
        /* вырабатываем ключ из пароля */
         if(( error = ak_mac_set_key_from_password( handle,
                            password, sizeof( password ), salt, sizeof( salt ))) != ak_error_ok ) {
           printf("secret key generation error\n");
           goto exit_local;
          }
      }

     /* проверяем, что алгоритм допускает использование синхропосылки (инициализационного вектора) */
      if( ak_mac_is_iv_settable( handle )) {
         if(( error = ak_mac_set_iv( handle, iv, ak_mac_get_iv_size( handle ))) != ak_error_ok ) {
           printf("assigning iv error\n");
           goto exit_local;
         }
      }

     /* проводим вычисления и выводим результаты */
      buffer = ak_mac_ptr( handle, data, sizeof( data ), NULL );
      if( ak_error_get_value() == ak_error_ok ) {
        char *str = ak_buffer_to_hexstr( buffer, ak_false );
        printf("%s [%u bytes]\n\n", str, (unsigned int) ak_buffer_get_size( buffer ));
        free( str );
        ak_buffer_delete( buffer );
      }

     /* уничтожаем дескриптор */
      exit_local: ak_handle_delete( handle );
      ++idx;
  } /* конец while */
  exit:
 return ak_libakrypt_destroy();
}
