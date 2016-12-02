 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 size_t idx = 0;
 ak_oid oid = NULL;

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();
 /* сначала вывод всех доступных OID подряд */
  for( idx = 0; idx < ak_oids_get_count(); idx++ ) {
    oid = ak_oids_get_oid( idx );
    printf(" %s [%s]\n", ak_oid_get_name( oid ), ak_oid_get_id( oid ));
  }

 /* потом поиск поиск по заданным параметрам */
  oid = ak_oids_find_by_name( "streebog256" );
  printf("\n founded by name: %s [%s]\n", ak_oid_get_name( oid ), ak_oid_get_id( oid ));
  oid = ak_oids_find_by_id( "2.16.840.1.101.3.4.2.3" );
  printf(" founded by id:   %s [%s]\n", ak_oid_get_name( oid ), ak_oid_get_id( oid ));

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
