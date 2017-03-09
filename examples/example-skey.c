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
  char *str = NULL;
  ak_uint8 gost3412_2015_key[32] = {
       0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  ak_uint8 out[32];
  ak_uint8 a[8] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe };
  ak_uint8 b[8] = { 0x3d, 0xca, 0xd8, 0xc2, 0xe5, 0x01, 0xe9, 0x4e };

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
   return ak_libakrypt_destroy();
  }

  // ak_random generator = ak_random_new_file("/dev/random");
  // ak_block_cipher_key key = ak_block_cipher_key_new_magma_random( generator );
  // ak_block_cipher_key key = ak_block_cipher_key_new_magma_password( "password", 8 );
  ak_block_cipher_key key = ak_block_cipher_key_new_magma_ptr( gost3412_2015_key, ak_false );
  print_key( &key->key );

  key->encrypt( &key->key, a, out );
  printf("out: %s\n", str = ak_ptr_to_hexstr( out, 8, ak_true )); free( str );
  printf("out: %s\n", str = ak_ptr_to_hexstr( b, 8, ak_true )); free( str );

  key->decrypt( &key->key, b, out );
  printf("in:  %s\n", str = ak_ptr_to_hexstr( out, 8, ak_true )); free( str );
  printf("in:  %s\n", str = ak_ptr_to_hexstr( a, 8, ak_true )); free( str );

  key = ak_block_cipher_key_delete( key );

 return ak_libakrypt_destroy();
}
