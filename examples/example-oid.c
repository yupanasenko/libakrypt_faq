 #include <stdio.h>
 #include <libakrypt.h>

/* предварительное описание функции вывода информации об OID */
 void print_oid_info( ak_handle );

 int main( void )
{
  ak_handle handle = ak_error_wrong_handle;
  const char *good = "streebog512"; /* это имя функции хеширования */
  const char *wrong = "2.16.840.1.101.3.4.2.3"; /* это OID функции SHA2-256 */

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* выводим информацию о всех доступных OID библиотеки
    (для поиска всех используется параметр undefined_engine) */
  handle = ak_libakrypt_find_oid_by_engine( undefined_engine );
  while( handle != ak_error_wrong_handle ) {

    /* если мы действительно нашли OID - выводим информацию о нем */
     if( ak_handle_get_engine( handle ) == oid_engine ) print_oid_info( handle );
      else printf("broken handle\n");

    /* ищем следующий OID с тем же типом криптографического механизма */
     handle = ak_libakrypt_findnext_oid_by_engine( handle, undefined_engine );
  }

 /* выводим информацию об общем количестве OID библиотеки */
 printf("total count of oid's: %lu\n", (unsigned long int) ak_libakrypt_oids_count( ));

 /* ищем OID по его имени */
  printf("\nsearch results:\n");
  if(( handle = ak_libakrypt_find_oid_by_name( good )) != ak_error_wrong_handle )
     print_oid_info( handle );
   else printf("oid with name \"%s\" not found\n", good );

 /* ищем OID по его цифровому идентификатору (последовательности чисел, разделенных точками */
  if(( handle = ak_libakrypt_find_oid_by_id( wrong )) != ak_error_wrong_handle )
    print_oid_info( handle );
  else printf("oid with id \"%s\" not found\n", wrong );

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}

/* реализация функции вывода информации об OID */
 void print_oid_info( ak_handle handle )
{
  printf("%s: %s (%s) [%s, %s]\n",
    ak_handle_get_engine_str( handle ),
    ak_libakrypt_oid_get_name( handle ),
    ak_libakrypt_oid_get_id( handle ),
    ak_libakrypt_oid_get_engine_str( handle ),
    ak_libakrypt_oid_get_mode_str( handle )
  );
}
