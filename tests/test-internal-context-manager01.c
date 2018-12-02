/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий внутренние механизмы работы структуры управления контекстами
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_context_manager.h>
 #include <ak_mac.h>
 #include <ak_bckey.h>
 #include <ak_sign.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
 void print_current_state_of_context_manager( void );

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  ak_pointer ctx = NULL;
  ak_handle handle = ak_error_wrong_handle, delhandle, delhandle2;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( NULL ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

 /* добавляем в менеджер несколько базовых объектов */
  printf(" - adding hash functions\n" );
  handle = ak_hash_new_streebog256( NULL );
  handle = ak_hash_new_streebog512( NULL );
  delhandle = ak_hash_new_gosthash94( NULL ); /* удаляемый пользователем контекст */

  printf(" - adding blcok ciphers\n" );
  if(( ctx = malloc( sizeof( struct bckey ))) != NULL ) {
    ak_bckey_context_create_magma( ctx );
    ak_bckey_context_set_key_random( ctx, &ak_libakrypt_get_context_manager()->key_generator );
    handle = ak_libakrypt_add_context( ctx, block_cipher, "magma random key" );
  }
  if(( ctx = malloc( sizeof( struct bckey ))) != NULL ) {
    ak_bckey_context_create_kuznechik( ctx );
    ak_bckey_context_set_key_random( ctx, &ak_libakrypt_get_context_manager()->key_generator );
    handle = ak_libakrypt_add_context( ctx, block_cipher, "kuznechik random key" );
  }


  printf(" - adding message authentication codes\n" );
  if(( ctx = malloc( sizeof( struct omac ))) != NULL ) {
    ak_omac_context_create_kuznechik( ctx );
    ak_omac_context_set_key_random( ctx, &ak_libakrypt_get_context_manager()->key_generator );
    handle = ak_libakrypt_add_context( ctx, omac_function, "OMAC key over kuznechik" );
  }
  if(( ctx = malloc( sizeof( struct omac ))) != NULL ) {
    ak_omac_context_create_magma( ctx );
    ak_omac_context_set_key_random( ctx, &ak_libakrypt_get_context_manager()->key_generator );
    handle = ak_libakrypt_add_context( ctx, omac_function, "OMAC key over magma" );
  }

  if(( ctx = malloc( sizeof( struct hmac ))) != NULL ) {
    ak_hmac_context_create_streebog256( ctx );
    ak_hmac_context_set_key_random( ctx, &ak_libakrypt_get_context_manager()->key_generator );
    handle = ak_libakrypt_add_context( ctx, hmac_function, "HMAC key over streebog256" );
  }
  delhandle2 = handle; /* удаляемый пользователем контекст */

  if(( ctx = malloc( sizeof( struct hmac ))) != NULL ) {
    ak_hmac_context_create_streebog512( ctx );
    ak_hmac_context_set_key_random( ctx, &ak_libakrypt_get_context_manager()->key_generator );
    handle = ak_libakrypt_add_context( ctx, hmac_function, "HMAC key over streebog512" );
  }
  if(( ctx = malloc( sizeof( struct hmac ))) != NULL ) {
    ak_hmac_context_create_gosthash94( ctx );
    ak_hmac_context_set_key_random( ctx, &ak_libakrypt_get_context_manager()->key_generator );
    handle = ak_libakrypt_add_context( ctx, hmac_function, "HMAC key over gosthash94_csp" );
  }

 /* удаляем часть контекстов */
  printf(" - deleting of two contexts\n" );
  ak_handle_delete( delhandle );
  ak_handle_delete( delhandle2 );

 /* добавляем часть контекстов */
  printf(" - adding a digital signature context\n" );
  if(( ctx = malloc( sizeof( struct signkey ))) != NULL ) {
    ak_signkey_context_create_streebog256( ctx,
                                       (const ak_wcurve ) &id_rfc4357_gost_3410_2001_paramSetA );
    ak_signkey_context_set_key_random( ctx, &ak_libakrypt_get_context_manager()->key_generator );
    handle = ak_libakrypt_add_context( ctx, hmac_function,
                                   "private key for GOST R 34.10-2012 with RFC 4357 paramSetA" );
  }

 /* текущее состояние менеджера контекстов */
  printf(" - current state of context manager\n" );
  print_current_state_of_context_manager();

 return ak_libakrypt_destroy();
}


/* ----------------------------------------------------------------------------------------------- */
 void print_current_state_of_context_manager( void )
{
  size_t i = 0;
  ak_context_manager manager = ak_libakrypt_get_context_manager();

  for( i = 0; i < ak_min( 12, manager->size ); i++ ) {
     ak_context_node node = manager->array[i];
     printf(" [%02lu]: ", i );
     if( node == NULL ) printf( "null\n");
      else {
        printf("%s\n", (char *)node->description.data );
        printf("\t algorithm: %s (%s)\n", node->oid->name, node->oid->id );
        printf("\t handle: %016llx\n", node->id );
        printf("\t status: %d\n", node->status );
      }
  }
}

/* ----------------------------------------------------------------------------------------------- */
