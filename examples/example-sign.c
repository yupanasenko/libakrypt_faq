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
  /* d = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"; */
  ak_uint64 key[ak_mpzn256_size]  =
    { 0x1D19CE9891EC3B28LL, 0x1B60961F49397EEELL, 0x10ED359DD39A72C1LL, 0x7A929ADE789BB9BELL };

  /* е = 2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5 */
  ak_uint64 e[ak_mpzn256_size]  =
    { 0x67ECE6672B043EE5LL, 0xCE52032AB1022E8ELL, 0x88C09C52E0EEC61FLL, 0x2DFBC1B372D89A11LL };

  /* k = 77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3 */
  ak_uint64 k[ak_mpzn256_size]  =
    { 0x4FED924594DCEAB3LL, 0x6DE33814E95B7FE6LL, 0x2823C8CF6FCC7B95LL, 0x77105C9B20BCD312LL };

  ak_wcurve wc = (ak_wcurve) &id_tc26_gost3410_2012_256_test_paramset;
  struct signkey sk;
  ak_uint8 out[64];
  char *str = NULL;

  ak_libakrypt_create( ak_function_log_stderr );

  printf("\ncreate: %d (size bytes: %ld)\n",
                    ak_signkey_create_streebog256( &sk, wc ), wc->size*sizeof( ak_uint64 ));

  ak_signkey_context_set_key( &sk, &key, 32 );
  print_skey( &sk.key );
/*  sk.key.remask( &sk.key );
  print_skey( &sk.key );

  printf("hash   (e): %s\n", str = ak_ptr_to_hexstr( e, 32, ak_true )); free( str );
  printf("random (k): %s\n", str = ak_ptr_to_hexstr( k, 32, ak_true )); free( str );

  memset( out, 0, 64 );
  ak_signkey_context_sign_values( &sk, k, e, out );

  printf("sign: %s\n\n", str = ak_ptr_to_hexstr( out, 64, ak_true )); free( str );
  print_skey( &sk.key );
*/
  ak_signkey_destroy( &sk );
 return ak_libakrypt_destroy();
}
