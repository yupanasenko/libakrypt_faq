#include <stdio.h>
#include <libakrypt.h>
#include <ak_skey.h>
#include <ak_hash.h>
#include <ak_parameters.h>

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
 /* тестовое значение ключа из ГОСТ Р 34.12-2015 */
  ak_uint32 test_3412_2015_key[8] = {
    0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff };
  ak_uint64 out_text = 0;
  ak_uint64 in_3412_2015_text = 0xfedcba9876543210, out_3412_2015_text = 0x4ee901e5c2d8ca3d;
  char *str = NULL;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
   return ak_libakrypt_destroy();
  }

  ak_block_cipher_key key = ak_block_cipher_key_magma_new_buffer( test_3412_2015_key, ak_false );
  print_key( &key->key );

  key->encrypt( &key->key, &in_3412_2015_text, &out_text );
  printf("out: %s\n", str = ak_ptr_to_hexstr( &out_text, 8, ak_true )); free( str );
  printf("out: %s\n", str = ak_ptr_to_hexstr( &out_3412_2015_text, 8, ak_true )); free( str );

  key->decrypt( &key->key, &out_3412_2015_text, &out_text );
  printf("in:  %s\n", str = ak_ptr_to_hexstr( &out_text, 8, ak_true )); free( str );
  printf("in:  %s\n", str = ak_ptr_to_hexstr( &in_3412_2015_text, 8, ak_true )); free( str );

  key = ak_block_cipher_key_delete( key );

 return ak_libakrypt_destroy();
}
