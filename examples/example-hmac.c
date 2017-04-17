 #include <stdio.h>
 #include <libakrypt.h>
 #include <ak_skey.h>

 ak_uint8 key[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
 };

 ak_uint8 data[16] = {
  0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00
 };

 ak_uint8 R256[32] = {
  0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
  0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
 };

 void print_hmac_key( ak_hmac_key hkey )
{
  char *str = NULL;
  ak_resource res = hkey->key.resource;

  printf("key:       %s\n", str = ak_buffer_to_hexstr( &hkey->key.key )); if( str ) free( str );
  printf("mask:      %s\n", str = ak_buffer_to_hexstr( &hkey->key.mask )); if( str ) free( str );
  printf("icode:     %s", str = ak_buffer_to_hexstr( &hkey->key.icode )); if( str ) free( str );
  if( ak_skey_check_icode_xor( &hkey->key )) printf(" (Ok)\n"); else printf(" (No)\n");
  printf("number:    %s\n", ak_buffer_get_str( &hkey->key.number ));

  printf("resource:  %lu\n", res.counter );
  if( hkey->key.oid == NULL ) printf("oid:      (null)\n");
   else printf("oid:       %s (%s)\n", ak_oid_get_name( hkey->key.oid ), ak_oid_get_id( hkey->key.oid ));
  printf("hash oid:  %s (%s)\n", ak_oid_get_name( hkey->ctx->oid ), ak_oid_get_id( hkey->ctx->oid ));
  printf("\n");
}


 int main( void )
{
 char *str = NULL;
 int error = ak_error_ok;
 ak_buffer result = NULL;

 ak_libakrypt_create( ak_function_log_stderr );

 ak_hmac_key hkey = ak_hmac_key_new_ptr( ak_hash_new_streebog256(), key, 32 );
 print_hmac_key( hkey );

 printf("update:     %d\n", error = ak_hmac_key_update( hkey, data, 16 ));
 ak_error_set_value( ak_error_ok );
 result = ak_hmac_key_finalize( hkey, data, 16, NULL );
 printf("finalize:   %d\n", ak_error_get_value());
 printf("result:     %s\n", str = ak_buffer_to_hexstr( result )); free( str );
 printf("R 50.1.113: %s\n", str = ak_ptr_to_hexstr( R256, 32, ak_false )); free( str );

 hkey = ak_hmac_key_delete( hkey );
 result = ak_buffer_delete( result );

 return ak_libakrypt_destroy();
}
