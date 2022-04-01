/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_xts.c                                                                                  */
/*  - содержит реализацию режимов шифрования, построенных по принципу гамма-коммутатор-гамма.      */
/*     подробности смотри в IEEE P 1619,                                                           */
/*     а также в статье https://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

#ifdef AK_HAVE_STDALIGN_H
 #include <stdalign.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует алгоритм двухключевого шифрования, описываемый в стандарте IEEE P 1619.

    \note Для блочных шифров с длиной блока 128 бит реализация полностью соответствует
    указанному стандарту. Для шифров с длиной блока 64 реализация использует преобразования,
    в частности вычисления к конечном поле \f$ \mathbb F_{2^{128}}\f$,
    определенные для 128 битных шифров.

    @param encryptionKey Ключ, используемый для шифрования информации
    @param authenticationKey Ключ, используемый для преобразования синхропосылки и выработки
    псевдослучайной последовательности
    @param in Указатель на область памяти, где хранятся входные (открытые) данные
    @param out Указатель на область памяти, куда будут помещены зашифровываемые данные
    @param size Размер входных данных (в октетах)
    @param iv Указатель на область памяти, где находится синхропосылка (произвольные данные).
    @param iv_size Размер синхропосылки в октетах, должен быть отличен от нуля.
    Если размер синхропосылки превышает 16 октетов (128 бит), то оставшиеся значения не используются.

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_xts( ak_bckey encryptionKey,  ak_bckey authenticationKey,
                        ak_pointer in, ak_pointer out, size_t size, ak_pointer iv, size_t iv_size )
{
  int error = ak_error_ok;
  ak_int64 jcnt = 0, blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
#ifdef AK_HAVE_STDALIGN_H
  alignas(16)
#endif
  ak_uint64 tweak[2], t[2], *tptr = t;

 /* проверяем целостность ключа */
  if( encryptionKey->key.check_icode( &encryptionKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                               "incorrect integrity code of encryption key value" );
  if( authenticationKey->key.check_icode( &authenticationKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                           "incorrect integrity code of authentication key value" );

 /* проверяем ресурс ключа аутентификации */
  if( authenticationKey->key.resource.value.counter < (ssize_t)( authenticationKey->bsize >> 3 ))
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of authentication cipher key" );
   else authenticationKey->key.resource.value.counter -= ( authenticationKey->bsize >> 3 );

 /* вырабатываем начальное состояние вектора */
  memset( tweak, 0, sizeof( tweak ));
  memcpy( tweak, iv, ak_min( iv_size, sizeof( tweak )));

  if( authenticationKey->bsize == 8 ) {
    authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );
    tweak[1] ^= tweak[0];
    authenticationKey->encrypt( &authenticationKey->key, tweak+1, tweak+1 );
  } else
      authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );

 /* вычисляем количество блоков */
  blocks = ( ak_int64 )( size/encryptionKey->bsize );
  if( size != blocks*encryptionKey->bsize )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* изменяем ресурс ключа */
  if( encryptionKey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of encryption cipher key" );
   else encryptionKey->key.resource.value.counter -= blocks;

 /* запускаем основной цикл обработки блоков информации */
   switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          *tptr = *inptr^*(tweak+jcnt); inptr++;
          encryptionKey->encrypt( &encryptionKey->key, tptr, tptr );
          *outptr = *tptr ^ *(tweak+jcnt); outptr++;
          --blocks;
          tptr++;

          if( !(jcnt = 1 - jcnt)) { /* изменяем значение tweak */
            tptr = t;
            t[0] = tweak[0] >> 63; t[1] = tweak[1] >> 63;
            tweak[0] <<= 1; tweak[1] <<= 1;
            tweak[1] ^= t[0];
            if( t[1] ) tweak[0] ^= 0x87;
          }
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
         /* шифруем */
          t[0] = *inptr^*tweak; inptr++;
          t[1] = *inptr^*(tweak+1); inptr++;

          encryptionKey->encrypt( &encryptionKey->key, t, t );
          *outptr = t[0]^*tweak; outptr++;
          *outptr = t[1]^*(tweak+1); outptr++;
          --blocks;

         /* изменяем значение tweak */
          t[0] = tweak[0] >> 63;
          t[1] = tweak[1] >> 63;
          tweak[0] <<= 1;
          tweak[1] <<= 1;
          tweak[1] ^= t[0];
          if( t[1] ) tweak[0] ^= 0x87;
       }
       break;
   }

 /* очищаем */
  if(( error = ak_ptr_wipe( tweak, sizeof( tweak ), &encryptionKey->key.generator )) != ak_error_ok )
   ak_error_message( error, __func__ , "wrong wiping of tweak value" );

 /* перемаскируем ключ */
  if(( error = encryptionKey->key.set_mask( &encryptionKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of encryption key" );
  if(( error = authenticationKey->key.set_mask( &authenticationKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of authentication key" );

  return error;
}

/* нижеследующий фрагмент выглядит более современно,
   но дает скорость на 0.5 МБ в секунду медленнее.
   возможно, я что-то делаю совсем не так....

   #include <immintrin.h>

   _m128i gamma = _mm_set_epi64x( tweak[1], tweak[0] );
   _m128i data = _mm_set_epi64x( *(inptr+1), *inptr ); inptr += 2;

         data = _mm_xor_si128( data, gamma );
         encryptionKey->encrypt( &encryptionKey->key, &data, &data );
         data = _mm_xor_si128( data, gamma );
         *outptr = _mm_extract_epi64( data, 0 ); outptr++;
         *outptr = _mm_extract_epi64( data, 1 ); outptr++;
         --blocks;                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует обратное преобразование к алгоритму, реализуемому с помощью
    функции ak_bckey_encrypt_xts().

    @param encryptionKey Ключ, используемый для шифрования информации
    @param authenticationKey Ключ, используемый для преобразования синхропосылки и выработки
    псевдослучайной последовательности
    @param in Указатель на область памяти, где хранятся входные (зашифрованные) данные
    @param out Указатель на область памяти, куда будут помещены расшифрованные данные
    @param size Размер входных данных (в октетах)
    @param iv Указатель на область памяти, где находится синхропосылка (произвольные данные).
    @param iv_size Размер синхропосылки в октетах, должен быть отличен от нуля.
    Если размер синхропосылки превышает 16 октетов (128 бит), то оставшиеся значения не используются.

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_xts( ak_bckey encryptionKey,  ak_bckey authenticationKey,
                        ak_pointer in, ak_pointer out, size_t size, ak_pointer iv, size_t iv_size )
{
  int error = ak_error_ok;
  ak_int64 jcnt = 0, blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
#ifdef AK_HAVE_STDALIGN_H
  alignas(16)
#endif
  ak_uint64 tweak[2], t[2], *tptr = t;

 /* проверяем целостность ключа */
  if( encryptionKey->key.check_icode( &encryptionKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                               "incorrect integrity code of encryption key value" );
  if( authenticationKey->key.check_icode( &authenticationKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                           "incorrect integrity code of authentication key value" );

 /* проверяем ресурс ключа аутентификации */
  if( authenticationKey->key.resource.value.counter < (ssize_t)( authenticationKey->bsize >> 3 ))
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of authentication cipher key" );
   else authenticationKey->key.resource.value.counter -= ( authenticationKey->bsize >> 3 );

 /* вырабатываем начальное состояние вектора */
  memset( tweak, 0, sizeof( tweak ));
  memcpy( tweak, iv, ak_min( iv_size, sizeof( tweak )));

  if( authenticationKey->bsize == 8 ) {
    authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );
    tweak[1] ^= tweak[0];
    authenticationKey->encrypt( &authenticationKey->key, tweak+1, tweak+1 );
  } else
      authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );

 /* вычисляем количество блоков */
  blocks = ( ak_int64 )( size/encryptionKey->bsize );
  if( size != blocks*encryptionKey->bsize )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* изменяем ресурс ключа */
  if( encryptionKey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of encryption cipher key" );
   else encryptionKey->key.resource.value.counter -= blocks;

 /* запускаем основной цикл обработки блоков информации */
   switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          *tptr = *inptr^*(tweak+jcnt); inptr++;
          encryptionKey->decrypt( &encryptionKey->key, tptr, tptr );
          *outptr = *tptr ^ *(tweak+jcnt); outptr++;
          --blocks;
          tptr++;

          if( !(jcnt = 1 - jcnt)) { /* изменяем значение tweak */
            tptr = t;
            t[0] = tweak[0] >> 63; t[1] = tweak[1] >> 63;
            tweak[0] <<= 1; tweak[1] <<= 1;
            tweak[1] ^= t[0];
            if( t[1] ) tweak[0] ^= 0x87;
          }
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
         /* шифруем */
          t[0] = *inptr^*tweak; inptr++;
          t[1] = *inptr^*(tweak+1); inptr++;

          encryptionKey->decrypt( &encryptionKey->key, t, t );
          *outptr = t[0]^*tweak; outptr++;
          *outptr = t[1]^*(tweak+1); outptr++;
          --blocks;

         /* изменяем значение tweak */
          t[0] = tweak[0] >> 63;
          t[1] = tweak[1] >> 63;
          tweak[0] <<= 1;
          tweak[1] <<= 1;
          tweak[1] ^= t[0];
          if( t[1] ) tweak[0] ^= 0x87;
       }
       break;
   }

 /* очищаем */
  if(( error = ak_ptr_wipe( tweak, sizeof( tweak ), &encryptionKey->key.generator )) != ak_error_ok )
   ak_error_message( error, __func__ , "wrong wiping of tweak value" );

 /* перемаскируем ключ */
  if(( error = encryptionKey->key.set_mask( &encryptionKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of encryption key" );
  if(( error = authenticationKey->key.set_mask( &authenticationKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of authentication key" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/* реализация режима аутентифицирующего шифрования xtsmac                                          */
/*                                                                                                 */
/* в редакции статьи A.Yu.Nesterenko,
   Differential properties of authenticated encryption mode based on universal hash function (XTSMAC),
   2021 XVII International Symposium "Problems of Redundancy in Information and Control Systems".
   IEEE, 2021. P. 39-44, doi: https://doi.org/10.1109/REDUNDANCY52534.2021.9606446                 */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, содержащая текущее состояние внутренних переменных режима `xtsmac`
   аутентифицированного шифрования. */
 typedef struct xtsmac_ctx {
  /*! \brief Текущее значение имитовставки. */
   ak_uint64 sum[2];
  /*! \brief Вектор, используемый для маскирования шифруемой информации. */
   ak_uint64 gamma[6];
  /*! \brief Размер обработанных зашифровываемых/расшифровываемых данных в битах. */
   ssize_t pbitlen;
  /*! \brief Размер обработанных ассоциированных данных в битах. */
   ssize_t abitlen;
  /*! \brief Флаги состояния контекста. */
   ak_uint32 flags;
} *ak_xtsmac_ctx;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста перед вычислением имитовставки и шифрованием информации

    Функция вычисляет начальное значение внутреннего состояния `gamma`
    из заданного значения синхропосылки с помощью равенства `gamma = CBC( K, iv, 0 )`,
    т.е. зашифровывает синхропосылку, переданную в аргументах функции,
    в режиме `cbc` с использованием нулевого вектора в качестве синхропосылки.

    \param actx контекст алгоритма xtsmac
    \param akey ключ аутентификации (должен быть ключом блочного алгоритма шифрования)
    \param iv указатель на область памяти, где хранится синхропосылка.
    \param iv_size размер синхропосылки (в октетах, ожадаемое значение -- два блока)

    \note Ожидаемый размер синхропосылки должен составлять два блока блочного шифра.
    Если аргумент `iv_size` содержит меньшую длину, то синхропосылка дополняется нулями
    в старших разрядах. Если `iv_size` большую длину, то лишние октеты отбрасываются.

    \return В случае успеха функция возвращает ноль (ak_error_ok). В случае
    возникновения ошибки возвращается ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_clean( ak_pointer actx,
                                       ak_pointer akey, const ak_pointer iv, const size_t iv_size )
{
  size_t b2 = 0;
  int error = ak_error_ok;
  ak_xtsmac_ctx ctx = actx;
  ak_uint8 ivcbc[16], in[32];
  ak_bckey authenticationKey = akey;

  if( authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");
  if( authenticationKey->key.oid->engine != block_cipher )
    return ak_error_message( ak_error_oid_engine, __func__,
                                                      "using non block cipher authentication key" );
  if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
  if( !iv_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using initial vector of zero length" );
 /* обнуляем необходимое */
  memset( ctx, 0, sizeof( struct xtsmac_ctx ));

 /* формируем исходное значение gamma */
  memset( in, 0, sizeof( in ));
  memcpy( in, iv, ak_min( iv_size, b2 = ( authenticationKey->bsize << 1 )));

  printf("in: %s\n", ak_ptr_to_hexstr( in, b2, ak_false ));


//  memset( ivcbc, 0, authenticationKey->bsize );
//  memset( ptcbc, 0, sizeof( ptcbc ));
//  memcpy( ptcbc, iv, ak_min( iv_size, 2*authenticationKey->bsize )); /* переносим не более 2х блоков */
//  if(( error = ak_bckey_encrypt_cbc( authenticationKey, ptcbc,
//                 ctx->gamma, 2*authenticationKey->bsize, ivcbc, sizeof( ivcbc ))) != ak_error_ok )
//    ak_error_message( error, __func__, "incorrect initialization of gamma values" );

  ak_aead_set_bit( ctx->flags, ak_aead_initialization_bit );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Очистка контекста перед шифрованием информации
    \details Функция-заглушка, используемая для инициализации контекста универсального алгоритма
    аутентифицированного шифрования.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_encryption_clean( ak_pointer ectx,
                                      ak_pointer ekey, const ak_pointer iv, const size_t iv_size )
{
  ak_xtsmac_ctx ctx = ectx;
  if(( ctx->flags&ak_aead_initialization_bit ) == 0 )
    return ak_error_message( ak_error_aead_initialization, __func__ ,
                                                             "using non initialized aead context");
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_update( ak_pointer actx,
                                 ak_pointer akey, const ak_pointer adata, const size_t adata_size )
{
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_encryption_update( ak_pointer actx, ak_pointer ekey, ak_pointer akey,
                                          const ak_pointer in, ak_pointer out, const size_t size )
{
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_decryption_update( ak_pointer actx, ak_pointer ekey, ak_pointer akey,
                                          const ak_pointer in, ak_pointer out, const size_t size )
{
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_finalize( ak_pointer actx,
                                           ak_pointer akey, ak_pointer out, const size_t out_size )
{
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                создание контекста aead алгоритма                                */
/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст aead алгоритма
    \param crf флаг необходимости создания ключа шифрования
    \return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_xtsmac_magma( ak_aead ctx, bool_t crf )
{
   int error = ak_error_ok;

   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   memset( ctx, 0, sizeof( struct aead ));
   if(( ctx->ictx = malloc( sizeof( struct xtsmac_ctx ))) == NULL )
     return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   if(( error = ak_aead_create_keys( ctx, crf, "xtsmac-magma" )) != ak_error_ok ) {
     if( ctx->ictx != NULL ) free( ctx->ictx );
     return ak_error_message( error, __func__, "incorrect secret keys context creation" );
   }

   ctx->tag_size = ctx->iv_size = ctx->block_size = 16; /* длина 2х блоков алгоритма Магма */
   ctx->auth_clean = ak_xtsmac_authentication_clean;
   ctx->auth_update = ak_xtsmac_authentication_update;
   ctx->auth_finalize = ak_xtsmac_authentication_finalize;
   ctx->enc_clean = ak_xtsmac_encryption_clean;
   ctx->enc_update = ak_xtsmac_encryption_update;
   ctx->dec_update = ak_xtsmac_decryption_update;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст aead алгоритма
    \param crf флаг необходимости создания ключа шифрования
    \return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_xtsmac_kuznechik( ak_aead ctx, bool_t crf )
{
   int error = ak_error_ok;

   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   memset( ctx, 0, sizeof( struct aead ));
   if(( ctx->ictx = malloc( sizeof( struct xtsmac_ctx ))) == NULL )
     return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   if(( error = ak_aead_create_keys( ctx, crf, "xtsmac-kuznechik" )) != ak_error_ok ) {
     if( ctx->ictx != NULL ) free( ctx->ictx );
     return ak_error_message( error, __func__, "incorrect secret keys context creation" );
   }

   ctx->tag_size = ctx->block_size = 16; /* длина блока алгоритма Кузнечик */
   ctx->iv_size = 32;
   ctx->auth_clean = ak_xtsmac_authentication_clean;
   ctx->auth_update = ak_xtsmac_authentication_update;
   ctx->auth_finalize = ak_xtsmac_authentication_finalize;
   ctx->enc_clean = ak_xtsmac_encryption_clean;
   ctx->enc_update = ak_xtsmac_encryption_update;
   ctx->dec_update = ak_xtsmac_decryption_update;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                функции прямой реализации, без использования контекста aead                      */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует режим шифрования для блочного шифра с одновременным вычислением
    имитовставки. На вход функции подаются как данные, подлежащие зашифрованию,
    так и ассоциированные данные, которые не зашифровываются. При этом имитовставка вычисляется
    для всех переданных на вход функции данных.

    Режим `xtsmac` должен использовать для шифрования и выработки имитовставки два различных ключа -
    в этом случае длины блоков обрабатываемых данных для ключей должны совпадать (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если указатель на ключ имитозащиты равен `NULL`, то возбуждается ошибка.
    Если указатель на ключ шифрования равен `NULL`, то данные не зашифровываются, однако
    имитовставка вычисляется.

    \note Данный режим не позволяет обрабатывать сообщения, длина которых менее 16 октетов.

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на зашифровываеме данные;
    @param out указатель на зашифрованные данные;
    @param size размер зашифровываемых данных в байтах, должен быть не менее 16 октетов;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, куда будет помещено значение имитовставки;
           память должна быть выделена заранее;
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно
           превышать 16 октетов; если значение icode_size, то возвращается запрашиваемое количество
           старших байт результата вычислений.

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_xtsmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                   const size_t size, const ak_pointer iv, const size_t iv_size,
                                                       ak_pointer icode, const size_t icode_size )
{
  int error = ak_error_ok;
  struct xtsmac_ctx ctx; /* контекст структуры, в которой хранятся промежуточные данные */
  ak_random generator = NULL;

  printf("%s\n", __func__ );

 /* проверки ключей */
  if(( error = ak_xtsmac_authentication_clean( &ctx, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
    if( authenticationKey != NULL ) ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),
                                                   &((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__,
                                           "incorrect initialization of internal xtsmac context" );
  }
//  if( encryptionKey != NULL ) {
//    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
//    return ak_error_message( ak_error_not_equal_data, __func__,
//                                                    "different block sizes for given secret keys");
//  }

 /* в начале обрабатываем ассоциированные данные */
  generator = &((ak_bckey)authenticationKey)->key.generator;
//  if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey, adata, adata_size ))
//                                                                              != ak_error_ok ) {
//    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), generator );
//    return ak_error_message( error, __func__, "incorrect hashing of associated data" );
//  }

// /* потом зашифровываем данные */
//  if( encryptionKey != NULL ) {
//    if(( error = ak_xtsmac_encryption_update( &ctx, encryptionKey, authenticationKey,
//                                                               in, out, size )) != ak_error_ok ) {
//      ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)encryptionKey)->key.generator );
//      return ak_error_message( error, __func__, "incorrect encryption of plain data" );
//    }
//  }
//   else { /* если ключа шифрования нет, то вычисляем имитовставку от оставшизся данных,
//             если длина обработанных ранее ассоциированных данных не кратна длине обрабатываемого блока,
//             то следующий фрагмент приведет к ошибке */
//    if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey,
//                                                                    in, size )) != ak_error_ok ) {
//      ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), generator );
//      return ak_error_message( error, __func__, "incorrect authentication of plain data" );
//    }
//   }

// /* в конце - вырабатываем имитовставку */
//  if(( error = ak_xtsmac_authentication_finalize( &ctx,
//                                         authenticationKey, icode, icode_size )) != ak_error_ok )
//    ak_error_message( error, __func__, "incorrect finanlize of integrity code" );

  ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), generator );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных. Требования к передаваемым параметрам
    аналогичны требованиям, предъявляемым к параметрам функции ak_bckey_encrypt_xtsmac().

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на расшифровываемые данные;
    @param out указатель на область памяти, куда будут помещены расшифрованные данные;
           данный указатель может совпадать с указателем in;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, в которой хранится значение имитовставки;
    @param icode_size размер имитовставки в байтах; значение не должно превышать 16 октетов;

    @return Функция возвращает \ref ak_error_ok, если значение имитовставки совпало с
            вычисленным в ходе выполнения функции значением; если значения не совпадают,
            или в ходе выполнения функции возникла ошибка, то возвращается код ошибки.             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_xtsmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  ak_uint8 icode2[16];
  int error = ak_error_ok;
  struct xtsmac_ctx ctx; /* контекст структуры, в которой хранятся промежуточные данные */
  ak_random generator = NULL;

  printf("%s\n", __func__ );

 /* проверки ключей */
  if(( error = ak_xtsmac_authentication_clean( &ctx, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
    if( authenticationKey != NULL ) ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),
                                                   &((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__,
                                           "incorrect initialization of internal xtsmac context" );
  }
  if( encryptionKey != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                    "different block sizes for given secret keys");
  }

 /* в начале обрабатываем ассоциированные данные */
  generator = &((ak_bckey)authenticationKey)->key.generator;
  if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), generator );
    return ak_error_message( error, __func__, "incorrect hashing of associated data" );
  }

 /* потом расшифровываем данные */
  if( encryptionKey != NULL ) {
    if(( error = ak_xtsmac_decryption_update( &ctx, encryptionKey, authenticationKey,
                                                             in, out, size )) != ak_error_ok ) {
      ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)encryptionKey)->key.generator );
      return ak_error_message( error, __func__, "incorrect encryption of plain data" );
    }
  }
   else { /* если ключа шифрования нет, то вычисляем имитовставку от оставшизся данных,
             если длина обработанных ранее ассоциированных данных не кратна длине обрабатываемого блока,
             то следующий фрагмент приведет к ошибке */
    if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey,
                                                                    in, size )) != ak_error_ok ) {
      ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), generator );
      return ak_error_message( error, __func__, "incorrect authentication of encrypted data" );
    }
   }

 /* в конце - вырабатываем имитовставку */
  memset( icode2, 0, 16 );
  if(( error = ak_xtsmac_authentication_finalize( &ctx,
                                         authenticationKey, icode2, icode_size )) != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), generator );
    return ak_error_message( error, __func__, "incorrect finanlize of integrity code" );
  }

  ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), generator );
  if( ak_ptr_is_equal_with_log( icode2, icode, icode_size )) return ak_error_ok;

 return ak_error_not_equal_data;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_xts.c  */
/* ----------------------------------------------------------------------------------------------- */
