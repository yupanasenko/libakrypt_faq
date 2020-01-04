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
 #include <ak_asn1_keys.h>

 int main( void )
{
  struct skey key;
  char filename[256], exec[512];
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };

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

 /* экспортируем ключ в файловый контейнер */
  ak_skey_context_export_to_derfile_with_password( &key, filename, sizeof( filename ), "password", 8 );
  ak_skey_context_destroy( &key );

 /* пытаемся вывести зашифрованное содержимое */
  printf("key encoded to %s file\n", filename );
  #ifdef LIBAKRYPT_HAVE_WINDOWS_H
    ak_snprintf( exec, sizeof(exec), "aktool.exe a %s", filename );
  #else
    ak_snprintf( exec, sizeof(exec), "./aktool a %s", filename );
  #endif
    system(exec);




  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
