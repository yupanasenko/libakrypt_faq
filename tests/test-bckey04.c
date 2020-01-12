/* Пример иллюстрирует процедуры преобразования секретного ключа
   в der-последовательность
   Внимание! Используются неэкспортируемые функции.

   test-bckey04.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_skey.h>
 #include <ak_asn1_keys.h>

/* определяем функцию, которая будет имитировать чтение пароля пользователя */
 int get_user_password( char *password, size_t psize )
{
  memset( password, 0, psize );
  ak_snprintf( password, psize, "password" );
 return ak_error_ok;
}

 int main( void )
{
  size_t count = 0;
  struct bckey key;
  ak_asn1 asn = NULL;
  int result = EXIT_FAILURE;
  char filename[256], exec[512];

 /* тестовый ключ, который помещается в контейнер */
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };
 /* тевтовые данные, на которых проверяется корректность шифрования на считанном */
  ak_uint8 in[18] = {
    0x0a, 0x55, 0xe4, 0x32, 0x20, 0xa1, 0x01, 0xfe, 0xaa,
    0x1a, 0x65, 0xf4, 0x42, 0x30, 0xb1, 0x11, 0x0e, 0xba };
  ak_uint8 out1[18], out2[18], iv[4] = { 0x00, 0xff, 0xe1, 0x1c };

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем ключ, который будет сохранен в ключевом контейнере,
    и инициализуем его указанным выше константным значением */
  ak_bckey_context_create_magma( &key );
  ak_bckey_context_set_key( &key, testkey, sizeof( testkey ));
 /* выводим созданный ключ в консоль */
  ak_skey_context_print_to_file( &key.key, stdout );

 /* зашифровываем данные */
  ak_bckey_context_ctr( &key, in, out1, sizeof( in ), iv, sizeof( iv ));
 /* экспортируем ключ в файловый контейнер */
  ak_bckey_context_export_to_derfile_with_password( &key, filename, sizeof( filename ), "password", 8 );
 /* уничтожаем ключ */
  ak_bckey_context_destroy( &key );

 /* выводим проверочные данные в консоль,
    поскольку ключ, входные данные и iv одинаковы, то при различных
    запусках данное значение должно быть постоянно */
  printf("encrypted test data: %s\n", ak_ptr_to_hexstr( out1, sizeof( out1 ), ak_false ));

 /* пытаемся вывести зашифрованное содержимое */
  printf("key encoded to %s file\n\n", filename );
  #ifdef LIBAKRYPT_HAVE_WINDOWS_H
    ak_snprintf( exec, sizeof(exec), "aktool.exe a %s", filename );
  #else
    ak_snprintf( exec, sizeof(exec), "./aktool a %s", filename );
  #endif
    system(exec);

 /* цикл разбора ключевого контейнера
    начинаем с того, что определяем функцию чтения пароля */
   ak_libakrypt_set_password_read_function( get_user_password );

 /* теперь считываем ASN.1 дерево из файла */
  asn = malloc( sizeof( struct asn1 ));
  ak_asn1_context_create_from_derfile( asn, filename );
  if( ak_asn1_context_check_key_container( asn, &count )) {
    size_t i = 0;
    ak_asn1 akey = NULL;
    ak_oid oid = NULL;

    printf("container has %u keys\n", (unsigned int)count );
    for( i = 0; i < count; i++ ) {
      /* получаем ASN.1 структуру из файла */
       ak_asn1_context_get_asn1_key_from_container( asn, &akey, i, &oid );
       if( oid == NULL ) continue;
       printf( "[%02u] loaded key info: %s (OID: %s, engine: %s, mode: %s)\n",
           (unsigned int)i, oid->names[0], oid->id, ak_libakrypt_get_engine_name( oid->engine ),
                                                          ak_libakrypt_get_mode_name( oid->mode ));
      /* создаем ключ и тестируем, что алгоритм расшифрования работает корректно */
       if( oid->engine == block_cipher ) {
         if( ak_bckey_context_create_asn1( &key, akey, oid ) != ak_error_ok ) continue;
         ak_skey_context_print_to_file( &key.key, stdout );
        /* зашифровываем данные */
         ak_bckey_context_ctr( &key, in, out2, sizeof( in ), iv, sizeof( iv ));
        /* сравниваем результат */
         printf("encrypted test data: %s ", ak_ptr_to_hexstr( out2, sizeof( out2 ), ak_false ));
         if( ak_ptr_is_equal( out1, out2, sizeof( out1 ))) {
           printf("(Ok)\n");
           result = EXIT_SUCCESS;
         }
          else printf("(Wrong)\n");
        /* уничтожаем ключ */
         ak_bckey_context_destroy( &key );
       }
    }
   }
    else printf("container has'nt keys\n");
  ak_asn1_context_delete( asn );

  ak_libakrypt_destroy();
 return result;
}
