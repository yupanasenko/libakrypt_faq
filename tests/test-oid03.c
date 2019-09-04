/* Тестовый пример, иллюстрирующий процедуры поиска oid по заданному криптографическому
   механизму, а также использование oid для создания и удаления функций хеширования.
   Пример использует неэкспортируемые функции.

   test-oid03.c
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
 ak_uint8 data[64], string[512];
 ak_uint8 test[12] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb };

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* перебираем все oid для функций хэширования и их параметров */
  oid = ak_oid_context_find_by_engine( hash_function );

  while( oid != NULL ) {
    if( oid->mode == kbox_params ) {
      ak_ptr_to_hexstr_static( oid->data, 16*8, string, 512, ak_false );
      printf("\nkbox: %s (%s)\ndata: %s\n", oid->name, oid->id, string );
    }
    if( oid->mode == algorithm ) {
      size_t size;
      struct hash ctx;

     /* создаем контекст по oid, вычисляем код целостности и удаляем контекст */
      if( ak_hash_context_create_oid( &ctx, oid ) != ak_error_ok ) continue;

      ++count;
      printf("\n%s (OID: %s)\n", ctx.oid->name, ctx.oid->id );
      size = ak_hash_context_get_tag_size( &ctx );

      ak_hash_context_ptr( &ctx, test, sizeof( test ), data, size );
      ak_ptr_to_hexstr_static( data, size, string, sizeof( string ), ak_false );
      printf("code: %s\n", string );
      ak_hash_context_destroy( &ctx );
    }

   /* выполняем поиск следующего */
    oid = ak_oid_context_findnext_by_engine( oid, hash_function );
  }

  printf("founded %d hash functions\n", count );
  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
