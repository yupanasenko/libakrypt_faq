/* Тестовый пример, иллюстрирующий процедуры поиска oid по заданному криптографическому
   механизму, а также использование oid для создания и удаления функций хеширования.
   Пример использует неэкспортируемые функции.

   test-oid02.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_oid.h>
 #include <ak_hash.h>
 #include <ak_random.h>

 int main( void )
{
 ak_oid oid;
 int count = 0;
 ak_uint8 data[64];
 ak_uint8 test[12] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb };
 const char *names[10] = {
  "md_gost12_512", "cspa", "rsa", "dev-random",
  "id-tc26", "gost-mac", "1.2.643.7.1.2.1.2.2", "grasshopper" };

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* перебираем все oid для функций хэширования и их параметров */
  oid = ak_oid_context_find_by_engine( hash_function );

  while( oid != NULL ) {
    if( oid->mode == kbox_params ) {
      printf("\nkbox: %s (%s)\ndata: %s\n", oid->names[0], oid->id,
                                 ak_ptr_to_hexstr( oid->data, 16*8, ak_false ));
    }
    if( oid->mode == algorithm ) {
      size_t size;
      struct hash ctx;

     /* создаем контекст по oid, вычисляем код целостности и удаляем контекст */
      if( ak_hash_context_create_oid( &ctx, oid ) != ak_error_ok ) continue;

      ++count;
      printf("\n%s (OID: %s)\n", ctx.oid->names[0], ctx.oid->id );
      if(( size = ak_hash_context_get_tag_size( &ctx )) > sizeof( data )) continue;

      ak_hash_context_ptr( &ctx, test, sizeof( test ), data, size );
      printf("code: %s\n", ak_ptr_to_hexstr( data, size, ak_false ));
      ak_hash_context_destroy( &ctx );
    }

   /* выполняем поиск следующего */
    oid = ak_oid_context_findnext_by_engine( oid, hash_function );
  }
  printf("founded %d hash functions\n", count );


 /* поиск по имени */
  printf("\nsearching test:\n");
  for( count = 0; count < 8; count++ )
     if(( oid = ak_oid_context_find_by_ni( names[count] )) != NULL )
       printf(" + oid %s found (aka %s)\n", names[count], oid->names[0] );
      else printf(" - oid %s not found\n", names[count] );

  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
