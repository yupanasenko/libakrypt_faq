/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_cmac.c                                                                                 */
/*  - содержит реализацию общих функций для алгоритмов блочного шифрования.                        */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданной области памяти фиксированного размера.
   Используется алгоритм, который также называют OMAC1
   или [CMAC](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf).

   @param bkey Ключ алгоритма блочного шифрования, используемый для выработки имитовставки.
   Ключ должен быть создан и определен.
   @param in Указатель на входные данные для которых вычисляется имитовставка.
   @param size Размер входных данных в байтах.
   @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
   Размер выделяемой памяти должен совпадать с длиной блока используемого алгоритма
   блочного шифрования.
   @param out_size Ожидаемый размер имитовставки.

   @return В случае возникновения ошибки функция возвращает ее код, в противном случае
   возвращается \ref ak_error_ok (ноль)                                                            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_cmac( ak_bckey bkey, ak_pointer in,
                                          const size_t size, ak_pointer out, const size_t out_size )
{
  ak_int64 i = 0, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" ),
        #ifdef AK_LITTLE_ENDIAN
           one64[2] = { 0x02, 0x00 },
        #else
           one64[2] = { 0x0200000000000000LL, 0x00 },
        #endif
           blocks = (ak_int64)size/bkey->bsize,
           tail = (ak_int64)size%bkey->bsize;
 ak_uint64 yaout[2], akey[2], *inptr = (ak_uint64 *)in;

 /* проверяем, что длина входных данных больше нуля */
  if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                                 "using a data with zero length" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to result buffer" );
  if( !out_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using zero length of result buffer" );
 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                  "incorrect integrity code of secret key value" );

 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.value.counter < ( blocks + ( tail > 0 )))
    return ak_error_message( ak_error_low_key_resource, __func__ ,
                                                              "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= ( blocks + ( tail > 0 )); /* уменьшаем ресурс ключа */

  memset( akey, 0, sizeof( akey ));
  memset( yaout, 0, sizeof( yaout ));
  if( !tail ) { tail = bkey->bsize; blocks--; } /* последний блок всегда существует */

 /* основной цикл */
  switch( bkey->bsize ) {
   case  8 :
          /* здесь длина блока равна 64 бита */
            for( i = 0; i < blocks; i++, inptr++ ) {
               yaout[0] ^= inptr[0];
               bkey->encrypt( &bkey->key, yaout, yaout );
            }

          /* теперь ключи для завершения алгоритма */
            bkey->encrypt( &bkey->key, akey, akey );
            if( oc ) akey[0] = bswap_64( akey[0] );
            ak_gf64_mul( akey, akey, one64 );

            if( tail < (ak_int64) bkey->bsize ) {
              ak_gf64_mul( akey, akey, one64 );
              ((ak_uint8 *)akey)[tail] ^= 0x80;
            }

          /* теперь шифруем последний блок */
            if( oc ) {
               yaout[0] ^= bswap_64( akey[0] );
               for( i = 0; i < tail; i++ ) ((ak_uint8 *)yaout)[7-i] ^= ((ak_uint8 *)inptr)[tail-1-i];
            }
              else {
               yaout[0] ^= akey[0];
               for( i = 0; i < tail; i++ ) ((ak_uint8 *)yaout)[i] ^= ((ak_uint8 *)inptr)[i];
              }
            bkey->encrypt( &bkey->key, yaout, akey );
          break;

   case 16 :
          /* здесь длина блока равна 128 бит */
            for( i = 0; i < blocks; i++, inptr += 2 ) {
               yaout[0] ^= inptr[0];
               yaout[1] ^= inptr[1];
               bkey->encrypt( &bkey->key, yaout, yaout );
            }

          /* вырабатываем ключи для завершения алгортма */
            bkey->encrypt( &bkey->key, akey, akey );
            if( oc ) {
              ak_uint64 tmp = bswap_64( akey[0] );
              akey[0] = bswap_64( akey[1] );
              akey[1] = tmp;
            }
            ak_gf128_mul( akey, akey, one64 );
            if( tail < (ak_int64) bkey->bsize ) {
              ak_gf128_mul( akey, akey, one64 );
              ((ak_uint8 *)akey)[tail] ^= 0x80;
            }

          /* теперь шифруем последний блок*/
            if( oc ) {
               yaout[0] ^= bswap_64( akey[1] );
               yaout[1] ^= bswap_64( akey[0] );
               for( i = 0; i < tail; i++ ) ((ak_uint8 *)yaout)[15-i] ^= ((ak_uint8 *)inptr)[tail-1-i];
            }
             else {
              yaout[0] ^= akey[0];
              yaout[1] ^= akey[1];
              for( i = 0; i < tail; i++ ) ((ak_uint8 *)yaout)[i] ^= ((ak_uint8 *)inptr)[i];
             }
            bkey->encrypt( &bkey->key, yaout, akey );
          break;
  }

 /* копируем нужную часть результирующего массива и завершаем работу */
 if( oc ) memcpy( out, (ak_uint8 *)akey, ak_min( out_size, bkey->bsize ));
  else memcpy( out, (ak_uint8 *)akey+( out_size > bkey->bsize ? 0 : bkey->bsize-out_size ),
                                                                  ak_min( out_size, bkey->bsize ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует последовательную комбинацию режимов из ГОСТ Р 34.12-2015. В начале
    вычисляется имитовставка от объединения ассоцииированных данных и
    данных, подлежащих зашифрования. При этом предполагается, что ассоциированные данные
    расположены вначале. После этого, данные зашифровываются.

    Режим `ctr-cmac` \b должен использовать для шифрования и выработки имитовставки два
    различных ключа, при этом длины блоков обрабатываемых данных для ключей должны совпадать
    (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если указатель на ключ шифрования равен `NULL`, то шифрование данных не производится и указатель на
    зашифровываемые (plain data) и зашифрованные (cipher data) данные \b должен быть равен `NULL`;
    длина данных (size) также \b должна принимать нулевое значение.
    В этом случае результат работы функции должен быть эквивалентен результату работы
    функции ak_bckey_cmac().

    Если указатель на ключ выработки имитовставки равен `NULL`, то аутентификация данных не производится.
    В этом случае указатель на ассоциированные данные (associated data) \b должен быть равен `NULL`,
    указатель на имитовставку (icode) \b должен быть равен `NULL`, длина дополнительных данных \b должна
    равняться нулю.
    В этом случае результат работы функции должен быть эквивалентен результату работы
    функции ak_bckey_ctr().

    Ситуация, при которой оба указателя на ключ принимают значение `NULL` воспринимается как ошибка.

    \note В настоящий момент использована наиболее простая реализация алгоритма,
    предполагающая что ассоциированные данные и шифруемые данные находятся в памяти последовательно.
    Если это допущение невыполнено, то результат работы функции может быть непредсказуемым.

    @param encryptionKey ключ шифрования (указатель на struct bckey), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки)
           (указатель на struct bckey), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на зашифровываеме данные;
    @param out указатель на зашифрованные данные;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, куда будет помещено значение имитовставки;
           память должна быть выделена заранее; указатель может принимать значение NULL.
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;
           если значение icode_size меньше, чем длина блока, то возвращается запрашиваемое количество
           старших байт результата вычислений.

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_ctr_cmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  size_t sizeptr = 0;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                "using null pointers both to encryption and authentication keys" );
  if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
      return ak_error_message( ak_error_wrong_length, __func__,
                                                           "different block sizes for given keys");
  }
  if(( adata != NULL ) && ( adata_size != 0 )) {
    /* проверяем, что данные расположены в памяти последовательно */
     if( ((ak_uint8*)adata)+adata_size != (ak_uint8 *)in )
       return ak_error_message( ak_error_linked_data, __func__,
                                          "this function can't be applied to non sequenced data" );
     ptr = adata;
     sizeptr = adata_size + size;
  } else {
      ptr = iv;
      sizeptr = size;
    }

  if( authenticationKey != NULL ) {
    if(( error =
             ak_bckey_cmac( authenticationKey, ptr, sizeptr, icode, icode_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect data encryption" );
  }
  if( encryptionKey != NULL ) {
    if(( error = ak_bckey_ctr( encryptionKey, in, out, size, iv, iv_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect data encryption" );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных. Требования к передаваемым параметрам
    аналогичны требованиям, предъявляемым к параметрам функции ak_bckey_encrypt_ctr_cmac().

    @param encryptionKey ключ шифрования (указатель на struct bckey), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки)
           (указатель на struct bckey), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на расшифровываемые данные;
    @param out указатель на область памяти, куда будут помещены расшифрованные данные;
           данный указатель может совпадать с указателем in;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, в которой хранится значение имитовставки;
    @param icode_size размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;

    @return Функция возвращает \ref ak_error_ok, если значение имитовтсавки совпало с
            вычисленным в ходе выполнения функции значением; если значения не совпадают,
            или в ходе выполнения функции возникла ошибка, то возвращается код ошибки.             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_ctr_cmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  size_t sizeptr = 0;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                "using null pointers both to encryption and authentication keys" );
  if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
      return ak_error_message( ak_error_wrong_length, __func__,
                                                           "different block sizes for given keys");
  }
  if(( adata != NULL ) && ( adata_size != 0 )) {
    /* проверяем, что данные расположены в памяти последовательно */
     if( ((ak_uint8*)adata)+adata_size != (ak_uint8 *)in )
       return ak_error_message( ak_error_linked_data, __func__,
                                          "this function can't be applied to non sequenced data" );
     ptr = adata;
     sizeptr = adata_size + size;
  } else {
      ptr = iv;
      sizeptr = size;
    }

  if( encryptionKey != NULL ) {
    if(( error = ak_bckey_ctr( encryptionKey, in, out, size, iv, iv_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect data decryption" );
  }
  if( authenticationKey != NULL ) {
    ak_uint8 icode2[32];
    memset( icode2, 0, sizeof( icode2 ));

    if( ((ak_bckey)authenticationKey)->bsize > icode_size )
      return ak_error_message( ak_error_wrong_length, __func__,
                                                "using block cipher with very huge block length" );
    if(( error =
             ak_bckey_cmac( authenticationKey, ptr, sizeptr, icode2, icode_size )) != ak_error_ok )
      return ak_error_message( error, __func__,
                                             "incorrect calculation of data authentication code" );
     if( ak_ptr_is_equal( icode, icode2, icode_size )) error = ak_error_ok;
       else error = ak_error_not_equal_data;
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_cmac.c  */
/* ----------------------------------------------------------------------------------------------- */

