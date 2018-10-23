/* Цель настоящего примера - вывести список всех доступных в библиотеке oid,
   не смотря на то, что библиотека не предоставляет доступа к внутреннему
   массиву oid.
   Пример использует неэкспортируемые функции.

   test-internal-oid03.c
*/

 #include <stdio.h>
 #include <ak_oid.h>

 int main( void )
{
  size_t i;
  ak_oid oid;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr ))
    return ak_libakrypt_destroy();

 /* находим какой-нибудь OID
    поскольку мы не знаем какой OID в дальнейшем будет первым в массиве */
  if(( oid = ak_oid_context_find_by_engine( block_cipher )) == NULL ) {
    ak_error_message( ak_error_oid_engine, __func__, "cannot find a block cipher");
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  };

 /* движемся по массиву oid в конец (пока не найдем строку из неопределенных значений) */
  while(( oid->engine != undefined_engine ) && ( oid->mode != undefined_mode ))
     oid = (ak_oid)(((ak_uint8 *)oid) + sizeof( struct oid ));

 /* зная общее число oid - получаем первый */
  oid = (ak_oid)(((ak_uint8 *)oid) - ak_libakrypt_oids_count()*sizeof( struct oid ));

 /* выводим все oid, начиная с начала */
  for( i = 0; i < ak_libakrypt_oids_count(); i++ ) {
     printf("%s [%s (%s), oid: %s]\n",
        oid->name, ak_libakrypt_get_engine_name( oid->engine ),
                       ak_libakrypt_get_mode_name( oid->mode ), oid->id );
     oid = (ak_oid)(((ak_uint8 *)oid) + sizeof( struct oid ));
  }

 ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
