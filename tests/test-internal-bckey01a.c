/* Пример иллюстрирует процедуры размножения и выработки производных ключей,
   используемые в алгоритмах семейства acpkm
   Внимание! Используются неэкспортируемые функции.

   test-internal-bckey01a.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_bckey.h>

 void print_key_info( ak_bckey skey, char *message )
{
  size_t i = 0;

  printf("\n%s\n%s (%s)\nkey:\t", message, skey->key.oid->name, skey->key.oid->id );
  for( i = 0; i < skey->key.key.size; i++ ) printf("%02X", ((ak_uint8 *)skey->key.key.data)[i] );
  printf("\nmask:\t");
  for( i = 0; i < skey->key.key.size; i++ ) printf("%02X", ((ak_uint8 *)skey->key.mask.data)[i] );
  printf("\nicode:\t");
  for( i = 0; i < skey->key.icode.size; i++ ) printf("%02X", ((ak_uint8 *)skey->key.icode.data)[i] );
  if( skey->key.check_icode( &skey->key ) == ak_true ) printf(" (Ok)\n");
   else printf(" (Wrong)\n");

  skey->key.unmask( &skey->key ); /* снимаем маску */
  printf("\nreal:\t");
  for( i = 0; i < skey->key.key.size; i++ ) printf("%02X", ((ak_uint8 *)skey->key.key.data)[i] );

  if( strncmp( skey->key.oid->name, "magma", 5 ) == 0 ) {
    printf("\nreal:\t");
    for( i = 0; i < 8; i++ ) printf("%u ", ((ak_uint32 *)skey->key.key.data)[i] );
  }

  skey->key.set_mask( &skey->key );
  printf("\n");
}

 int test_cipher( char *name )
{
  size_t j = 0;
  struct bckey first, second;
  int result = 0, error = ak_error_ok, i = 0;
  ak_uint8 out[16], out2[16], key[32] = {
     0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
     0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80 };

  if(( error = ak_bckey_context_create_oid( &first,
                                   ak_oid_context_find_by_ni( name ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "creation error" );
    goto labex;
  }
  if(( error = ak_bckey_context_set_key( &first, key, 32, ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__, "assigning key value error" );
    goto labex;
  }
  print_key_info( &first, "first key" );

  if(ak_bckey_context_create_and_set_bckey( &second, &first ) != ak_error_ok ) {
    ak_error_message( error, __func__, "duplication error" );
    goto labex;

  }
  print_key_info( &second, "second key" );

 /* теперь мы начинаем выработку цепочки производных ключей */
  printf("\n-------------------------------------------------\n");
  for( i = 0; i < 5; i++ ) {
     ak_bckey_context_next_acpkm_key( &first );
     first.encrypt( &first.key, key, out );
     for( j = 0; j < first.bsize; j ++ ) printf(" %02X", out[j] );
     printf("\n");
  }
  printf("\n-------------------------------------------------\n");
  for( i = 0; i < 5; i++ ) {
     ak_bckey_context_next_acpkm_key( &second );
     second.encrypt( &second.key, key, out2 );
     for( j = 0; j < second.bsize; j ++ ) printf(" %02X", out2[j] );
     printf("\n");
  }
  if( memcmp( out, out2, first.bsize )) result = EXIT_FAILURE;
   else result = EXIT_SUCCESS;
  ak_bckey_context_destroy( &second );

 labex:
  printf("\n");
  ak_bckey_context_destroy( &first );
 return result;
}

 int main( void )
{
  ak_log_set_level( ak_log_maximum );
 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

  if( test_cipher( "magma" )) return EXIT_FAILURE;
  if( test_cipher( "kuznechik" )) return EXIT_FAILURE;

 return ak_libakrypt_destroy();
}
