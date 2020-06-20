#include <stdio.h>
#include <string.h>
#include <libakrypt.h>

 int main( void )
{
  size_t idx = 0;
  struct oid_info oid;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( NULL ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

 /* выводим все, что можем получить, а именно
     - идентификатор
     - доступные имена
     - тип криптографического преобразования
     - режим использования                    */
  printf("  N  %-25s %-40s %-20s %-20s\n", "oid(s)", "name(s)", "engine", "mode" );
  printf(" -----------------------------------------------------");
  printf("------------------------------------------------------\n");
  for( idx = 0; idx < ak_libakrypt_oids_count(); idx++ ) {
    size_t jdx = 0;
   /* получаем информацию об идентифкаторе с заданным номером */
    if(( ak_libakrypt_get_oid_by_index( idx, &oid )) != ak_error_ok ) break;
    if( oid.name[0] == NULL ) break; /* это нештатная ситуация, поскольку
               всегда должно быть определено одно имя и один идентификатор */

   /* выводим сначала с одним именем  */
    printf("%3u  %-25s %-40s %-20s %-20s\n",
           (unsigned int) idx, oid.id[0], oid.name[0],
	   ak_libakrypt_get_engine_name( oid.engine ),
	   ak_libakrypt_get_mode_name( oid.mode ));

   /* потом выводим остальные имена идентификатора */    
    while( oid.name[++jdx] != NULL ) {
      printf("%-30s %s\n", " ", oid.name[jdx] );
    }
  }

 return ak_libakrypt_destroy();
}
