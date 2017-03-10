#include <stdio.h>
#include <libakrypt.h>
#include <ak_skey.h>
#include <ak_hash.h>
#include <ak_context_manager.h>

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

 void print_status( ak_context_manager manager )
{
  size_t i = 0;

  printf("size:  %lu\n", manager->size );
  printf("imask: %lx\n", manager->imask );
  for( i = 0; i < manager->size;i++ ) {
   if( manager->array[i] == NULL ) printf("\n%02lu: (null)\n", i);
    else {
           ak_context_node node = manager->array[i];
           printf("\n%02lu: %s (id: %lu)\n", i, ak_buffer_get_str( node->description ), node->id );
           if( node->engine == block_cipher ) print_key( node->ctx );
           if( node->engine == hash_function ) {
             ak_oid oid = ak_hash_get_oid( node->ctx );
               printf("oid: %s (%s)\n", ak_oid_get_name( oid ), ak_oid_get_id( oid ));
           }
           if( node->engine == undefined_engine ) {
             printf("%s\n", ak_buffer_get_str( node->ctx ));
           }
         }
  }
}

 int main( void )
{
  size_t i = 0;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
   return ak_libakrypt_destroy();
  }

  struct context_manager mgr;
  ak_context_manager_create( &mgr, ak_random_new_lcg( ));

  for( i = 0; i < mgr.size; i++ ) {
     mgr.array[i] = ak_context_node_new(
                      ak_block_cipher_key_new_magma_password( "longhellostring", 2+i ),
                      30 + i,
                      block_cipher,
                      ak_buffer_new_str("simple block cipher key"),
                      ak_block_cipher_key_delete );
  }

  mgr.array[3] = ak_context_node_delete( mgr.array[3] );
  print_status( &mgr );

  ak_context_manager_morealloc( &mgr );
  print_status( &mgr );

  mgr.array[7] = ak_context_node_delete( mgr.array[7] );
  mgr.array[7] = ak_context_node_new( ak_hash_new_streebog512(), 4422, hash_function,
                           ak_buffer_new_str("hash function context"), ak_hash_delete );

  ak_context_manager_morealloc( &mgr );
  mgr.array[13] = ak_context_node_new( ak_buffer_new_str("SIMPLE BUFFER in context manager"), 1215, undefined_engine,
                         ak_buffer_new_str("buffer context"), ak_buffer_delete );

  print_status( &mgr );

  ak_context_manager_destroy( &mgr );
 return ak_libakrypt_destroy();
}
