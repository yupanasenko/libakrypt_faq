/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий внутренние механизмы работы структуры управления контекстами

 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>
 #include <ak_skey.h>
 #include <ak_hash.h>
 #include <ak_random.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
 void print_key( ak_skey skey );
 void print_hash( ak_hash ctx );
 void print_random( ak_random generator );
 void print_status( ak_context_manager );

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  size_t i = 0;
  ak_key key = ak_key_wrong;
  ak_random generator = NULL;
  struct context_manager manager;

 /* инициализируем библиотеку, в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( NULL ) != ak_true ) return ak_libakrypt_destroy();

 /* определяем структуру управления контекстами и генератор псевдо-случайных чисел */
  generator = ak_random_new_lcg();
  ak_context_manager_create( &manager, ak_random_new_lcg( ));

 /* слкучайным образом генерим контексты */
  for( i = 0; i < 12; i++ ) {
     switch( ak_random_uint8( generator )%3 )
    {
      case 0: key = ak_context_manager_add_ctx( &manager,
                           ak_bckey_new_magma_password( "longhellostring", 2+i ),
                           block_cipher,
                           ak_buffer_new_str("block cipher MAGMA key"),
                           ak_bckey_delete );
              printf("%02lu: added block cipher key %lx\n", i, key );
              break;

      case 1: key = ak_context_manager_add_ctx( &manager,
                           ak_random_uint8( generator) < 180 ?  /* несбалансированное условие */
                                        ak_hash_new_streebog256() : ak_hash_new_streebog512(),
                           hash_function,
                           ak_buffer_new_str("hash function from GOST R 34.12-2012 standard"),
                           ak_hash_delete );
              printf("%02lu: added hash function    %lx\n", i, key );
              break;

      case 2: key = ak_context_manager_add_ctx( &manager,
                           ak_buffer_new_str("simple BUFFER"),
                           undefined_engine,
                           ak_buffer_new_str("small description for string buffer"),
                           ak_buffer_delete );
              printf("%02lu: added buffer           %lx\n", i, key );
              break;
    }
  }
  printf("    added generator        %lx\n", ak_context_manager_add_ctx( &manager, generator,
     random_generator, ak_buffer_new_str("random generator, FIRST"), ak_random_delete ));

 /* удаляем несколько контекстов */
  manager.array[4] = ak_context_node_delete( manager.array[4] );
  manager.array[7] = ak_context_node_delete( manager.array[7] );

 /* добавляем еще один */
  ak_context_manager_add_ctx( &manager, ak_random_new_lcg(),
     random_generator, ak_buffer_new_str("random generator, SECOND"), ak_random_delete );

  print_status( &manager );

  ak_context_manager_destroy( &manager );
 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 void print_key( ak_skey skey )
{
  int i = 0;
  char *str = NULL;
  ak_resource res = skey->resource;

  printf("key:      %s\n", str = ak_buffer_to_hexstr( &skey->key )); if( str ) free( str );
  printf("mask:     %s\n", str = ak_buffer_to_hexstr( &skey->mask )); if( str ) free( str );
  printf("icode:    %s ", str = ak_buffer_to_hexstr( &skey->icode )); if( str ) free( str );
  if( ak_skey_check_icode_additive( skey )) printf("(Ok)\n"); else printf("(No)\n");
  printf("number:   %s\n", ak_buffer_get_str( &skey->number ));
  printf("resource: %lu\n", res.counter );
  if( skey->oid == NULL ) printf("oid:     (null)\n");
    else printf("oid:      %s (%s)\n", ak_oid_get_name( skey->oid ), ak_oid_get_id( skey->oid ));
  printf("random:   "); for( i = 0; i < 16; i++ ) printf("%02x ", ak_random_uint8( skey->generator ));
  printf("\n");
}

/* ----------------------------------------------------------------------------------------------- */
 void print_hash( ak_hash ctx )
{
  char *str = NULL;
  ak_oid oid = ak_hash_get_oid( ctx );
  ak_buffer result = ak_hash_data( ctx, "", 0, NULL );
  printf("algorithm: %s (%s)\n", ak_oid_get_name( oid ), ak_oid_get_id( oid ));
  printf("hash: %s\n", str = ak_buffer_to_hexstr( result )); if( str ) free( str );
  ak_buffer_delete( result );
}

/* ----------------------------------------------------------------------------------------------- */
 void print_random( ak_random generator )
{
  int i = 0;
  printf("random:   "); for( i = 0; i < 16; i++ ) printf("%02x ", ak_random_uint8( generator ));
  printf("\n");
}

/* ----------------------------------------------------------------------------------------------- */
 void print_status( ak_context_manager manager )
{
  size_t i = 0;
  printf("\nsize:  %lu\n", manager->size );
  printf("imask: %lx\n", manager->imask );
  for( i = 0; i < manager->size;i++ ) {
     if( manager->array[i] == NULL ) printf("\n%02lu: (null)\n", i);
     else {
            ak_context_node node = manager->array[i];
            printf("\n%02lu: %s (id: %lx)\n", i, ak_buffer_get_str( node->description ), node->id );
            if( node->engine == block_cipher ) print_key( node->ctx );
            if( node->engine == hash_function ) print_hash( node->ctx );
            if( node->engine == random_generator ) print_random( node->ctx );
            if( node->engine == undefined_engine ) {
              printf("%s\n", ak_buffer_get_str( node->ctx ));
            }
          }
  }
}

/* ----------------------------------------------------------------------------------------------- */
