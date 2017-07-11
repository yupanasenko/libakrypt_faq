 #include <stdio.h>
 #include <libakrypt.h>

 #include <ak_oid.h>

 int main( void )
{
 size_t idx = 0;
 const char *wrong = "2.16.840.1.101.3.4.2.3"; /* это OID функции SHA2-256 */

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

  ak_handle oid = 0;
  for( oid = 0; oid < 3; oid++ ) {
     ak_handle random = ak_random_new_oid( oid );
     printf("handle: %lu [engine: %s], random: %016lX\n", oid, ak_handle_get_engine_str(random), ak_random_uint64( random ));
  }

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
