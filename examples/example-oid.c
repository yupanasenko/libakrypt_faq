#include <stdio.h>
#include <string.h>
#include <libakrypt.h>

 int main( void )
{
  size_t idx = 0;
  const char *oid;
  oid_modes_t mode;
  const char **names;
  oid_engines_t engine;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

 /* выводим все, что можем получить */
  printf("  N  %-22s %-40s %-20s %-20s\n", "oid", "name(s)", "engine", "mode" );
  printf(" -----------------------------------------------------");
  printf("------------------------------------------------------\n");
  for( idx = 0; idx < ak_libakrypt_oids_count(); idx++ ) {
    size_t jdx = 0;
    if(( ak_libakrypt_get_oid_by_index( idx,
                         &engine, &mode, &oid, &names )) != ak_error_ok ) break;
    if( names[0] == NULL ) break;

    printf("%3u  %-22s %-40s %-20s %-20s\n",
      (unsigned int) idx, oid, names[0], ak_libakrypt_get_engine_name( engine ),
                                           ak_libakrypt_get_mode_name( mode ) );
    while( names[++jdx] != NULL )
      printf("%28s%s\n", " ", names[jdx] );
  }

 return ak_libakrypt_destroy();
}
