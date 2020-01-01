/* Пример иллюстрирует процедуры преобразования секретного ключа
   в der-последовательность
   Внимание! Используются неэкспортируемые функции.

   test-skey02.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_skey.h>
 #include <ak_asn1.h>
 #include <ak_tools.h>

 int main( void )
{
  size_t len = 0;
  struct skey key;
  ak_uint8 derkey[1024];
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };
  struct file fp;

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем ключ, который будет сохранен в ключевом контейнере,
    и инициализуем его указанным выше константным значением */
     ak_skey_context_create( &key, 32 );
     ak_skey_context_set_key( &key, testkey, 32 );
   /* устанавливаем oid и ресурс ключа */
     key.oid = ak_oid_context_find_by_name("magma");
     ak_skey_context_set_resource( &key, block_counter_resource, "magma_cipher_resource", 0, time(NULL)+2592000 );
     ak_skey_context_print_to_file( &key, stdout );

 /* экспортируем ключ в файловый контейнер,
    зашифровывая его на заданном пользователем пароле */
  len = sizeof( derkey );
  if( ak_skey_context_export_to_der_from_password( &key, "password", 8, derkey, &len ) == ak_error_ok )
    ak_asn1_fprintf_ptr( stdout, derkey, len, ak_true );

 /* сохраняем выработанное значение в файл */
  ak_file_create_to_write( &fp, "testkey.key" );
  ak_file_write( &fp, derkey, len );
  ak_file_close( &fp );

  ak_skey_context_destroy( &key );
  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
