/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2021 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_npecies.c                                                                              */
/*  - содержит реализацию схемы асимметричного шифрования                                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
 int ak_hybrid_encrypt_file( ak_hybrid_encryption_set set, ak_pointer scheme,
                  const char *filename, char *outfile, const size_t outsize, ak_random generator,
                                                    const char *password, const size_t pass_size )
{
  struct file ifp, ofp;
  int error = ak_error_ok;
  ak_int64 total = 0, maxlen = 0, value = 0, sum = 0;

   if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to random number generator" );
   if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to name of encrypted file" );
   if( set == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to encryption set" );
   if( set->mode->mode != aead ) return ak_error_message( ak_error_oid_mode, __func__,
                                                       "using non aead mode for data encryption" );

  /* формируем имя создаваемого файла */
   if( outsize > 0 ) {
     if( outsize < 12 ) return ak_error_message( ak_error_wrong_length, __func__, 
                                                       "buffer for output filename is too small" );
     ak_random_ptr( generator, outfile, 12 );
     strncpy( outfile, ak_ptr_to_hexstr( outfile, 12, ak_false ), outsize );
   }

   printf("infile: %s, outfile: %s\n", filename, outfile );/* <----------------------------------- DELME */

 /* формируем разбиение исходного файла */
   if(( error = ak_file_open_to_read( &ifp, filename )) != ak_error_ok ) {
     return ak_error_message_fmt( error, __func__, "wrong open a file (%s)", filename );
   }

 /* устраиваем перебор фрагментов исходного текста */
  total = ifp.size;
  printf("total: %lld\n", total );

  if(( value = set->fraction.value ) == 0 ) value = 10; /* количество фрагментов по-умолчанию */
  if( strstr( set->mode->name[0], "kuznechik" ) != NULL )
    maxlen = 16*ak_libakrypt_get_option_by_name( "kuznechik_cipher_resource" );
   else maxlen = 8*ak_libakrypt_get_option_by_name( "magma_cipher_resource" );

  printf("maxlen: %lld\n", maxlen );

 /* разбиение исходного файла на фрагменты длины
    от 4096 байт до maxlen, где maxlen определяется
    ресурсом секретного ключа */

  if( set->fraction.mechanism == count_fraction ) {
    maxlen = ak_max( 4096, ak_min( total/value, maxlen ));
  }
  if( set->fraction.mechanism == size_fraction ) {
    maxlen = ak_max( 4096, ak_min( value, maxlen ));
  }

  while( total > 0 ) {
   ak_int64 current = maxlen;
   if( set->fraction.mechanism == random_size_fraction ) {
     ak_random_ptr( generator, &current, 4 ); /* нам хватит 4х октетов */
     current %= ifp.size;
     if( current > maxlen ) current = maxlen; /* не очень большая */
     current = ak_max( 4096, current );     /* не очень маленькая */
   }
   current = ak_min( current, total );
   if(((total - current) > 0 ) && ((total - current) < 4096 )) current = total;
   printf("current: %lld\n", current );

   total -= current;
   sum += current;
  }
  if( sum != ifp.size ) ak_error_message( ak_error_wrong_length, __func__,
                         "the length of encrypted data is not equal to the length of plain data" );
  ak_file_close( &ifp );
 return ak_error_ok;
}


//{
//  ak_asn1 root, asn1;
//  ak_tlv tlv = NULL;
//  ak_npecies_scheme nps = ( ak_npecies_scheme ) scheme;




//  ak_asn1 asn = NULL;
//  ak_tlv tlv = NULL, bkmd = NULL;

//  ak_asn1_add_tlv( asn = ak_asn1_new(), tlv = ak_tlv_new_sequence( ));
//  ak_asn1_add_oid( tlv->data.constructed, ak_oid_find_by_name( "libakrypt-container" )->id[0] );
//  ak_asn1_add_tlv( tlv->data.constructed, bkmd = ak_tlv_new_sequence( ));

// /* формируем BasicKeyMetaData */
//  ak_asn1_add_oid( bkmd->data.constructed, ak_oid_find_by_name( "npecies-scheme-key" )->id[0] );
//  ak_asn1_add_tlv( bkmd->data.constructed, ak_tlv_new_sequence( ));
// return ak_error_undefined_function;
//}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_npecies.c  */
/* ----------------------------------------------------------------------------------------------- */
