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
  ak_uint64 key[ak_mpzn256_size]  = { 0x22220000ffffabcdLL, 0x1, 0x1, 0x3fffffffffffffffLL };
  struct signkey sk;
  ak_libakrypt_create( ak_function_log_stderr );

  printf("create: %d (size bytes: %ld)\n",
    ak_signkey_create_streebog256( &sk, (ak_wcurve) &id_tc26_gost3410_2012_256_test_paramset ),
    id_tc26_gost3410_2012_256_test_paramset.size*sizeof( ak_uint64 ));
  print_skey( &sk.key );

  ak_signkey_context_set_key( &sk, &key, sizeof(ak_uint64)*ak_mpzn256_size);
  print_skey( &sk.key );

  sk.key.remask( &sk.key );
  print_skey( &sk.key );

  и где же удаление ключа

 return ak_libakrypt_destroy();
}
