 #include <stdio.h>
 #include <libakrypt.h>

/* предварительное описание функции вывода информации об OID */
 void print_oid_info( ak_handle );

 int main( void )
{
  ak_handle handle = ak_error_wrong_handle;
  const char *wrong = "2.16.840.1.101.3.4.2.3"; /* это OID функции SHA2-256 */

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* выводим информацию о всех доступных OID библиотеки
    (для поиска всех используется параметр undefined_engine) */
  handle = ak_oid_find_by_engine( undefined_engine );
  while( handle != ak_error_wrong_handle ) {

    /* если мы действительно нашли OID - выводим информацию о нем */
     if( ak_handle_get_engine( handle ) == oid_engine ) print_oid_info( handle );
      else printf("broken handle\n");

    /* ищем следующий OID с тем же типом криптографического механизма */
     handle = ak_oid_findnext_by_engine( handle, undefined_engine );
  }

 /* ищем OID по его имени */
  print_oid_info( ak_oid_find_by_name( "streebog256" ));

 /* ищем OID по его цифровому идентификатору (последовательности чисел, разделенных точками */
  // print_oid_info( ak_oid_find_by_id( wrong ));

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}

/* реализация функции вывода информации об OID */
 void print_oid_info( ak_handle handle )
{
  printf("%s: ", ak_handle_get_engine_str( handle ));
  printf("%s (%s) ", ak_oid_get_name( handle ), ak_oid_get_id( handle ));
  printf("[%s, %s]\n", ak_oid_get_engine_str( handle ), ak_oid_get_mode_str( handle ));
}
