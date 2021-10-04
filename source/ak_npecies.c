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
  ak_asn1 root, asn1;
  ak_tlv tlv = NULL;
  ak_npecies_scheme nps = ( ak_npecies_scheme ) scheme;




//  ak_asn1 asn = NULL;
//  ak_tlv tlv = NULL, bkmd = NULL;

//  ak_asn1_add_tlv( asn = ak_asn1_new(), tlv = ak_tlv_new_sequence( ));
//  ak_asn1_add_oid( tlv->data.constructed, ak_oid_find_by_name( "libakrypt-container" )->id[0] );
//  ak_asn1_add_tlv( tlv->data.constructed, bkmd = ak_tlv_new_sequence( ));

// /* формируем BasicKeyMetaData */
//  ak_asn1_add_oid( bkmd->data.constructed, ak_oid_find_by_name( "npecies-scheme-key" )->id[0] );
//  ak_asn1_add_tlv( bkmd->data.constructed, ak_tlv_new_sequence( ));
 return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_npecies.c  */
/* ----------------------------------------------------------------------------------------------- */
