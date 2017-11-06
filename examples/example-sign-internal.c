 #include <stdio.h>
 #include <ak_sign.h>
 #include <ak_parameters.h>
 #include <libakrypt.h>

 char *str = NULL;

 void print_skey( ak_skey key )
{
  ak_uint64 st[ak_mpzn512_size];
  ak_uint64 one[ak_mpzn512_size] = ak_mpzn512_one;

  printf("number: %s\n", ak_buffer_get_str( &key->number ));
  printf("key:    %s\n", str = ak_ptr_to_hexstr( key->key.data, 32, ak_true )); free( str );
  printf("mask:   %s\n", str = ak_ptr_to_hexstr( key->mask.data, 32, ak_true )); free( str );
  printf("icode:  %s\n", str = ak_ptr_to_hexstr( key->icode.data, 8, ak_true )); free( str );

  memset( st, 0, sizeof( ak_uint64 )*ak_mpzn512_size );
  ak_mpzn_sub( st, ((ak_wcurve)key->data)->q, key->mask.data, ((ak_wcurve)key->data)->size );
  ak_mpzn_add_montgomery( st, st, key->key.data, ((ak_wcurve)key->data)->q, ((ak_wcurve)key->data)->size );
  ak_mpzn_mul_montgomery( st, st, one, ((ak_wcurve)key->data)->q, ((ak_wcurve)key->data)->nq, ((ak_wcurve)key->data)->size );
  printf("is_key: %s\n\n", str = ak_ptr_to_hexstr( st, 32, ak_true )); free( str );
}


 int main( void )
{
  int i = 0;
  struct signkey sk;
  struct verifykey pk;
  struct random generator;
  ak_buffer result = NULL;
  ak_uint64 ptr[8] = { 0xfffffffffffff65c, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0, 0x0, 0x0 };
  char *str = NULL, password[64];

  ak_libakrypt_create( ak_function_log_stderr );
  ak_random_create_lcg( &generator );

  if( ak_signkey_create_streebog512( &sk, (ak_wcurve)&id_tc26_gost3410_2012_512_paramsetA ) != ak_error_ok )
    return ak_libakrypt_destroy();

  printf("password: "); fflush( stdout );
  if( ak_password_read( password, 64 ) != ak_error_ok )
    return ak_libakrypt_destroy();
  printf("\n");

  if( ak_signkey_context_set_key_password( &sk, password, 64, "123", 3 ) != ak_error_ok )
    return ak_libakrypt_destroy();
   else print_skey( &sk.key );

  ak_verifykey_create_signkey( &pk, &sk );
  for( i = 0; i < 5; i++ ) {
     result = ak_signkey_context_sign_ptr( &sk, ptr, sizeof(ptr), NULL );
     printf("%s (%d)\n", str = ak_buffer_to_hexstr( result ), (int) ak_buffer_get_size( result ));

     if( ak_verifykey_context_verify_ptr( &pk,
                         ptr, sizeof(ptr), ak_buffer_get_ptr( result ))) printf("Sign is Ok\n");
      else printf("Sign is Wrong\n");

     ak_buffer_delete( result );
     free( str );
  }

  result = ak_signkey_context_sign_file( &sk, "data64.dat", NULL );
  printf("\nFile data64.dat\n%s (%d)\n",
     str = ak_buffer_to_hexstr( result ), (int) ak_buffer_get_size( result ));
  if( ak_verifykey_context_verify_file( &pk,
                         "data64.dat", ak_buffer_get_ptr( result ))) printf("Sign is Ok\n");
     else printf("Sign is Wrong\n");

  ak_buffer_delete( result );
  free( str );

  ak_signkey_destroy( &sk );
  ak_verifykey_destroy( &pk );
  ak_random_destroy( &generator );

 return ak_libakrypt_destroy();
}
