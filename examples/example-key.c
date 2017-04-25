 #include <stdio.h>
 #include <libakrypt.h>
 #include <ak_skey.h>
 #include <ak_hash.h>
 #include <ak_tools.h>
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


 int main( void )
{
  ak_key key;
  ak_bckey bkey = NULL;
  int error = ak_error_ok;
  char password[32], *str = NULL;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* вводим пароль */
  printf("password: ");
  if(( error = ak_password_read( password, 32 )) != ak_error_ok ) return ak_libakrypt_destroy();
  printf("\ninput value: %s (len: %u, hex: %s)\n",
                      password, (unsigned int) strlen(password),
                                 str = ak_ptr_to_hexstr( password, 32, ak_false ));
  free(str);

 /* создаем ключа из пароля */
  key = ak_context_manager_add_node( ak_libakrypt_get_context_manager(),
                                     bkey = ak_bckey_new_magma_password( password, strlen( password )),
                                     block_cipher,
                                     NULL,
                                     ak_bckey_delete );
  memset( password, 0, 32 );
  printf("handle: %ld\n", key );
  print_key( &bkey->key );

 return ak_libakrypt_destroy();
}


