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
/*                 реализация режима аутентифицирующего шифрования xtsmac                          */
/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup aead
 @{ */
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
/** @} */

/* ----------------------------------------------------------------------------------------------- */
 static const ak_uint64 pitable[8][256] = /* развернутая комбинация нелинейного и линейного преобразования */
{
 {
  0x8a0d2d5ea678b121,  0x91f991b6ef1242bc,  0xc08b93adccd252b0,  0xb884cd86b8fee1d0,
  0xe13fbc42eb98fd71,  0xedcae54d43ec6d07,  0x7972e2a3a378cf07,  0x0af79514dee26b89,
  0x36a5f45b23290d29,  0xbad3487c182c9990,  0xcbb6e84863868a79,  0x10cf36563b4d1a41,
  0xbf0665c03d920e0d,  0xa3ac4b0502cea4d8,  0xec204abda0fabe91,  0x39e20c1ff13cc474,
  0xa9221d8f670b51d4,  0xb789169ad31ddf8a,  0x0b7bfb28fe69f3ed,  0x9d4ffef650620af4,
  0xf80cedbdb84377eb,  0x6a0a2dda4f9fded8,  0x0e97d9b60ae9e9b0,  0xad9199e13dfa3885,
  0x98f14ea7c8f30e56,  0xb2f6113427777757,  0xb60912dcea47e545,  0xe81d4527ffb432bb,
  0x31fd99e23acaa644,  0x3e1dae679955e1dc,  0xaeb43fae2f30af7a,  0x850b4efb48e926d3,
  0x462672efa8e5ca66,  0xdaa2f98533f297d9,  0x57a9e5d7f6d6a636,  0x38701cbcb4bf37d6,
  0xdb20e929a5e8ca41,  0x441c20c8141548bd,  0x0f9bc59d1fc4e879,  0x2ff1111ce738751a,
  0x9e0765b4f13f3124,  0xca2c922f0086f31d,  0xb9d37dee57572aae,  0xa720fa71885115b8,
  0x3775e76a166710d5,  0x8974ce16c3b9cf48,  0x997eb1d9fbd9b4a4,  0x7cee8b8f08b3634f,
  0xd2b4ce642296e946,  0x253b21ef478bf543,  0x244e3edb003ca786,  0xc0ae192c20cd766e,
  0x0e912ed2e5537d01,  0xae5fd98a3dfa4baa,  0x5660327f6732ac7e,  0xd8ecd86d8a80783e,
  0x3b25e6162fa25feb,  0xe4f0157f3439cb3c,  0xadffe748ecf9c0e2,  0x35de5a0d5cd4d9bb,
  0xe73f431a85b5151f,  0xb7c4ccc796e83719,  0x9ba342b19bdf164f,  0x092559444340e964,
  0x04dbbd12ba75d178,  0x5705919aac29fc5a,  0x42504b9ccd9cd5a0,  0xfdcf32ee2af58d26,
  0x0d27810fa7e4a30e,  0xfd1b63d486ff6714,  0xcd0a3a9fd5206492,  0xa06e5fcbe7453738,
  0x305054b17b4d0ccb,  0x3caf6042b95582b5,  0xa1a3bef540b87856,  0xddaaded4b892517b,
  0x1734d80dc6f36c4d,  0x949cc9db61132594,  0xf976142f55cdf6c8,  0xf943a8eccca62fee,
  0x142c1fe4f41954d8,  0x506994bde0dabaaa,  0x5da65de6773da7b3,  0x91dcbb0776c197da,
  0xabc0cb6c0cb05200,  0x1daa69bf2578e833,  0x9c4ae0bddf44e2a3,  0xa5ffb952d1295782,
  0xc1acf4dfdfbfd8fb,  0xf667b86cd61ec001,  0xdddb4b7b41259986,  0x5b309ace1fe1fd13,
  0x64c41b1fcd892c99,  0x9162bb328a131d6b,  0x8b841926fa9aabf3,  0xe42c079f5591182d,
  0x885a893dc4853b1b,  0xa2f3528a697049b0,  0xd418de1b2ff143b1,  0x5b09b925668e9535,
  0xd8b5baeed656f35e,  0x96403e42233aff5f,  0xed37b86d35dbe40a,  0x0d9000cc4a00aff1,
  0x15496e9d0c0aae20,  0x2e6f54117b84d9e3,  0x466f21dea31fbf8d,  0x5dedc6f78623df5a,
  0x8ce3de58b6e74ddd,  0xc27296be57a8f772,  0x5b1f956a1bb3c3d7,  0xa84f1c7f00546559,
  0x16ad047934dfd87c,  0xc78c67c1d04eb96e,  0x04fb208c712f39bc,  0x6737718669ca5931,
  0x0d69011797f2474a,  0x86f035c05f6c023c,  0xd912d903dc484f0f,  0xd9e11d160b0a183c,
  0xd97a580962471f4e,  0x2979c26e5831a41d,  0x9de98eea374c07fb,  0x78782291383a1869,
  0xf3288f9ee6476f01,  0xcc39113c24e2e8b4,  0x18ec90556a81b0c4,  0xe6572e7c04b9d062,
  0xa79c3c3e526bcf4e,  0x871cdfcc047fe6eb,  0x1be113ab20789de5,  0x447715e6c1039b4d,
  0xf191d9b654975ef0,  0xf5f8264d90da3ab9,  0x8b03ee59409b3b01,  0xecbc3245d69ce0f6,
  0x63b88f7b6c2a27b4,  0x6dcbf4b748922bee,  0xca4feba629b02e96,  0xa2780319fa1a74ce,
  0x80a7d284a771f44a,  0xf887d8cbc55c0ed2,  0x57c88e8883ded062,  0x658544b6d02f2806,
  0x0de445887668558c,  0xdea663b98f4bed2e,  0x83435df4ff2d8071,  0x8657bf114b49c776,
  0x0bb912dcd9c9c978,  0xb301f0a82a298ba1,  0x0b7427969fc12a83,  0x5eb7c92c33f3a2de,
  0x81c3605855419183,  0xd76931188edab679,  0xe9453bc3ced3b1c3,  0xc15b93da2195eda3,
  0xa1f0a73a3b79e415,  0xb75dbb55c853427e,  0xc853dbb4c326f73f,  0x206522623036ef14,
  0x5f9ab9578fa9dad9,  0xfd94934e29759e6b,  0x8d41e4c51deeeeb0,  0x8575fd8eb41fd25d,
  0x78fd8627829860ff,  0xfb2ae3836ad71ca8,  0x57391de837575c70,  0x72452dd794e53f62,
  0xb38889d889ec52f2,  0x994ae93907cf1d69,  0x1150bd805bb2990c,  0xde8464ef3c78374e,
  0xedee51007c275d89,  0xac381cc6a3e65f35,  0x1ea5f1807857c676,  0x13cb7a261d715689,
  0x3a0e37d4ee02d85b,  0x17c27b7b377c7c7b,  0x1766d2a29151cec4,  0x9198db1c7c2d9e38,
  0xadefb7abf4d36631,  0x448536762cb90a84,  0xfae89984c1d0a0bf,  0xa63a220e5bca70da,
  0x75a503681326e366,  0x2186220939202a39,  0x999a129a403f4ac6,  0x96663bfa16295bd2,
  0xca06f01526f9be09,  0xe9876da3f9b8425f,  0x29ab4c25c131124f,  0x424970bdb0d98fe2,
  0x5d577f2a7fbeb1ff,  0x1a7bdc48f4cc9ac4,  0x5588123c0f1f319b,  0x9be2ee865b0f9395,
  0x31ba81abf3ca639c,  0x8c5981eb024f320d,  0x87ed0b0ecc5cafe9,  0x9efd9d73f3d2e8c3,
  0x16611f56967f5146,  0xbb023fe01c0c696f,  0xb7b5b9d1e640bbf3,  0x5cd217388371e7c5,
  0xebaa4556e68f6a16,  0xe399d4b168358ff3,  0xb6eb8e51cbead1a9,  0xd008a03621adec88,
  0x10adc8a5f6d273dc,  0xb4426dc7259f3f52,  0x0d4202ecb10e28c0,  0xb7d8dc45d5a83fbf,
  0xaf0fce46412d5d45,  0x0d6bea6e1c0184ff,  0xa9e1550979777d6f,  0x3f996423841e4d22,
  0x00a60a828c939f0f,  0xabfcbc9a16e5c388,  0x8a945a4e422748ff,  0xd0c03526af043b09,
  0x4b575619ca739de1,  0xdbd9c3d0e52e77f9,  0x780a9aadd2154944,  0x58cb23e428e834c8,
  0x244517690e7fa9b4,  0x938bf36e818d8d4b,  0x7611ab9dea4ab50c,  0x5a8890d6fd671391,
  0xae66f173459a3ec2,  0xe66107246c399af4,  0x0d1ef49fc85d1a54,  0xfe9b3a818dd15f12,
  0xf74e7c9536e86df5,  0xf079604becd0b91c,  0xc32d4969cf068767,  0xe0e93e7957d7d104,
  0x17da979aa3223fd6,  0x7bf968dc5bd4c8d7,  0x41c1fb32f56e3226,  0x7a8114b9e4c557a4,
  0x6a6c72452aad078b,  0x3767c63a5d467284,  0x1956beedf71d998e,  0x02b140bafd5f9b85,
  0xd4d95ced4c8a9d2a,  0xf4039160dc6526d9,  0x30be7a37a6408e86,  0x8db65483d947ee0c,
  0xafb884a62f46f1bc,  0xc29ae6860ee0e024,  0x7f50e3f28e9dbb51,  0x9acb55ba2b2218ee,
  0xac391b77ae2e0ac8,  0x374b85fd0b694f35,  0x75f575bec07b1359,  0x1a6c7c1accbd1e9c
 },
 {
  0x8bf57f606aa05964,  0xafaade06c02b0146,  0x48bc3b6a0030ada7,  0x9292c40896eb2b41,
  0x414096957af77e9a,  0x1e2cd33f3118237a,  0x5110569623c975a2,  0xf8d69501ac293f24,
  0x420564341dadfeaf,  0x013cbe8bef1d3baf,  0x4746a41b6b2d6c63,  0xe6a87e3164de8ff7,
  0x07f2d05c27f48758,  0x5fa9b707075bdd25,  0x16d739f044c94244,  0x450206df2537d1e1,
  0xa61fd6e4ab2af54d,  0x7ba3fcb059cc5936,  0xb195f1d3bc0056ee,  0xb916efe095595c6f,
  0x9357d269c1367e6b,  0xf4c6064cea832bda,  0x1232323adb7379f9,  0x0e649ca3bc220c86,
  0x1276ccbc2444f13d,  0x86d7e3b74e5838d9,  0xabe0d6d45c642008,  0x0ba711662828026e,
  0x3f44209df84f49be,  0xba09e98a3c5e2681,  0xee20b057c0084511,  0xb1691c52130584e4,
  0x92fabf7bacbb045a,  0xcf38c7b97bc55489,  0x086cf6b09f0a50da,  0x48eab2de1ab22a39,
  0xb2ba114708bdb684,  0x958637bba3521442,  0x0998c6a7b8b26549,  0x7624d7b40ac81a55,
  0x3948845a8b2d8476,  0x35e6c8268fd11cd7,  0xf2680ac97a24cc77,  0x00b5edf73b37e67c,
  0x63d51b079e03ae72,  0xa2371d06b0020418,  0x2ebf6e1aee6838b4,  0xd666104b441f0bfe,
  0x1b8c15e8f94bcd48,  0xed9226c2ecbb78ce,  0x47b96c32d1f15882,  0x992fa2b68f59b6b8,
  0x1ca733284ee0a159,  0x91158f1ff0decf05,  0x9b0b97b3e0d53e48,  0x52742eba181e4b3f,
  0xf8e206a7776c365b,  0x63393355878d9194,  0x7d00bfe7b711474b,  0x4cc0b1da91d87c5a,
  0x0b17c26fe922d07f,  0xf6053067d52745df,  0xaa42a711de4e2748,  0xfa310ee83cc9eea3,
  0x618ce85a2fc98fbc,  0xd7e587161ead0688,  0xf5ccfd9f15e88f53,  0x6306903031dedc6c,
  0x19e9cbd3cc6a6003,  0x1aee381853672c31,  0x256f6fc4466bdf3a,  0xe43762e93057fa75,
  0xbabccafd5deeaa24,  0xbd15c489515ff4c9,  0xe571637b63c760fb,  0x12b5ccf606a528fe,
  0xe5db27eecda1f547,  0xbdd6ab6e010973d9,  0x25ef29986cb6ebdb,  0xf3c5a3f61edc680f,
  0x663686606a80943e,  0x07e934148fbd75f2,  0x7da32a7406587096,  0x2d4b8b0fe99ef9c9,
  0xcce91eb55e344025,  0x3e2e3def02806728,  0xd336d7baab6ff2c0,  0x8c840dde460c6a15,
  0x86c830c211a4e118,  0xa224111260db1f77,  0x206becf7d6e13f33,  0xf5896aeccc688411,
  0x842a68c168ba1739,  0x86e7e0461299778b,  0x4a837b2f4660a56f,  0x7fac44b6b6d8545b,
  0x3c5e85185aeb12ea,  0x55a4d152669b1291,  0x2bc6daae6cd1b5e4,  0x981292dacd0b7e17,
  0xf4f491a8c6b98898,  0x213a779969ad5dc5,  0x2f2391fde0cef291,  0x369ce17df73f0938,
  0xcc261c9830821e10,  0x5507e85b0474366b,  0x4957aaac11c10ffa,  0x352e24987d59e9f6,
  0x459dae170feadd5d,  0xfcd5b4674b5bab27,  0xc218d6bc2c16fa69,  0x93fa67dc17ad2851,
  0xda5c91e91b62bbdb,  0xdb75992f29d70895,  0xbe4c7eb77c878b01,  0x0626349596397db5,
  0x0613d1d4d1c95299,  0x9ab875618b6d55ce,  0xe49893fc57522bd8,  0x1c8150fb666c8f67,
  0xf7cb3245b8fd5cb3,  0x7d65acc9e370e1c3,  0xa8a72e867c166cc1,  0x2f5d4d79b6499b63,
  0xd6ca4f82965749bf,  0x99cca50d93dbc4b8,  0x1f724fe159595dd6,  0x79deb566d8b3cfd1,
  0xd3f87e34ea9a891a,  0xc1f952d97ee2e4e8,  0xf86625a686420e69,  0xa5a7ae952afdf0c3,
  0xb0ba680d9bc5495d,  0xdb24fe699e3712fb,  0xf122e558ee92c4d9,  0x7f1d5eb7e1628e79,
  0x0fb60d23c3641867,  0xbe336d501b24e277,  0xe99ce4cd142c0dd2,  0x187f330adf608dc2,
  0x2a4c8599e7f365a1,  0x9c71d69ad8f79575,  0xf7f9daac9d92bc9d,  0xbcde7aaba1ede29e,
  0x58b4d252258a647f,  0x39f48d0c71da829d,  0x953c36e4ec50b647,  0xee6ac2112b42fe77,
  0x9195a75ca464de63,  0xe8619f3649ab1844,  0x949986a7860b9800,  0x341588fa60a777fd,
  0xf85c4218bc76b44a,  0x94b0b2d085c6b8a4,  0xce1dd5c179565ed1,  0x2e3b1bf6e35653fb,
  0xe4e176d875901972,  0x4ea8598605d929d0,  0x070e839db40ca97d,  0xa14f18c5a453a2c3,
  0x042282509de52421,  0xd08f2a2f77735b58,  0xfb05018b17e7a940,  0x2fdbb43eb595540e,
  0x0dfd23411cfdf1d0,  0xb2db43ff4b0c7477,  0x35daccd1ec2c8629,  0xc3f6e49d95f21d9c,
  0x38b17a91fc3599bd,  0x400247e56299e026,  0xd21e53fecc89f46f,  0x50486d6a52c58380,
  0x87f580ad0e45d144,  0xcc86d77b1d113ef5,  0xd13738c12271766f,  0xde96e9a5c3e720f2,
  0x30a4785e5f84defc,  0x6f84726a417af39a,  0xdf842cbe2668c94a,  0xedbf371a9483e4d2,
  0x0ecfef42bd6b3a84,  0x7eaa834ae3ee9d34,  0x163f4aac72a43277,  0x76463551c96041d2,
  0x0eae61a48802acfb,  0x08a1eb01eaa4ec3b,  0x60a5e8de24370b9c,  0x9d53384218d57240,
  0x538ff96eb1b4d6dc,  0xfb1810a33c999d54,  0x0ca75926c23df56f,  0x2c4bda4d03173db3,
  0xa69d6b6457e2f844,  0x9178e3d24c8f5bdd,  0x0032706f368ceaf3,  0x6f1cafc9291376dc,
  0xe24c01a57dd58730,  0xc2a6cd99bd7ed393,  0x0a5360f6aa1f5972,  0xed81abc1d1d214ae,
  0xef978541cd5b3ab1,  0x73a583dad4862639,  0x73382d6ea75db23b,  0x3a53d07143fed7a7,
  0xf896b855b4c53d38,  0x8d1436532e97dd2a,  0xe157f848457776c2,  0xa314dbd2c929dc1f,
  0x04ea0f30a417289b,  0xfeecfcb2e7f78b96,  0x873e9f613c9c8a62,  0xb723651081c5b3f3,
  0x50d9c6f37589d6c9,  0x09bf9b64339613c5,  0x757b0e38f76b4f2b,  0x183a62a569a5e771,
  0x70a13b04d4a9fbcd,  0x24b4e2391b209681,  0x8704108cf205a97e,  0xea03073229377a93,
  0xef627cf38f99d194,  0xc7be3ce4c242b204,  0x76c415aa3e0116f4,  0xb1030673445369cc,
  0x30f9aca8df2aba7e,  0xf7656ca54dacda11,  0x832ed929c62e961c,  0x0e97c1ac3596870e,
  0x2b0943c4ebba0968,  0x6eeed4b88462b577,  0xc48ffeb3452d4dde,  0xbba0e9f407710af7,
  0xc0e8ec79652b2080,  0x9f82c42f72d59e0d,  0x6e04bda9faf6f2f2,  0xd77166674f87eb1e,
  0x97296f4993b19e47,  0xc9064eb1bcf343d6,  0xe8a5b3f5f66e3603,  0x5f1d3c7fb8d98700,
  0x550444dc4311cd4f,  0x7b988df02def83ab,  0xbfad483488750eee,  0x1df9c099385d312f,
  0x7ea23ff3f0356a54,  0x03da934bd660b06c,  0xb3db3cb007d5ebfd,  0xe0ff6227f50f735e,
  0x8cdf7c87340553c1,  0x36aef0b8e4c0eb79,  0x857b3280d220d604,  0xbbc6830c2dfc766d,
  0x9f43706c8bee581a,  0x2238627070b34f16,  0xe3d4efe597791427,  0x9cb23e46c5420082
 },
 {
  0x2bc2b9160ef3dd7e,  0x12704fa97431e194,  0xbbd1a8787a96fcb6,  0xe3367b02a350c9b4,
  0xcab8a21f6993a196,  0xd738fafddad92ab0,  0x2fec627caba29378,  0x2e662553425af57b,
  0xcd84010a9d3863ad,  0xf3a82680e8f6264f,  0x5cfc770074579876,  0x4f4fdf913f03e520,
  0xc8a7b3696d2ee994,  0x5e624103d43e9388,  0xa5e644feb481707a,  0x86cfe2c27d7c83e4,
  0xf818258a258f9247,  0x72c3c8d9514f0943,  0x7db8029d69fa87e7,  0xd67f07bb3a4deb8b,
  0x48e688efbe8b0b79,  0x785f1e60b3ac7b0a,  0xc39360177ca23465,  0x0a31523721cdf4f6,
  0xe58840439119b503,  0x63c63feb37ca5463,  0xe9df153cf2a997ad,  0x43d818b0e39cd569,
  0x09aa14e1df945caf,  0x504989d68d54713f,  0x3b9e6a57e8c73ff8,  0x79026650acdc614a,
  0x13d6270b3e0a5cbf,  0x5d33ed1a6ba6f88f,  0x5b55ba6ccfe49368,  0xd6623474016bf2f1,
  0xac5c47bb54311dc1,  0x309467d74b1bb984,  0xe271cec4317d9ee5,  0x8beaef0de5057e08,
  0xd84ee35a07fbb483,  0xa34d145865f92a61,  0xd9639806b44588c1,  0x5d24c3c4cafa6cbf,
  0xda852d6384e46615,  0xa2b3b7e71923da26,  0x20fb1aacf253472d,  0xe7064e135decab90,
  0xccc84b85f56d12a4,  0x2350e776449cc883,  0xf8c23219822765f3,  0x08550af1764b5e54,
  0xc45975ee98de2204,  0x840789ab37baec45,  0xcf97a6ec868a8d5d,  0xac369e43576d504c,
  0xcb82ac4d16997007,  0x51d63cb92491285e,  0x7a5fc0cbb8faaba5,  0x572eb1fe7e422e3a,
  0xd0eb375a63435689,  0x4ee6961d7634d2a5,  0xf4051d8ae68e00ce,  0x8159cd81229199ee,
  0x4c4aa8360f4de63f,  0xb290c3ec374be8b4,  0x42143fb0ab1be733,  0x704b664d9a011f19,
  0xfd673f1bf8d5a1f9,  0x1b2d4788e4306d44,  0x98385621602798ed,  0xd2ca8dccfffea7db,
  0x1f6f0a00dfac8466,  0xebb120e758d80700,  0xe519797c215c204c,  0x01f5237a35bd0d0c,
  0x0747786edd318e87,  0x0a918ce3e84a6988,  0x149d4462f0e9899f,  0x0a0742f3297c8188,
  0x36226ce004a6db5e,  0xcd0ece5ed255dfd4,  0xab83466348708dac,  0x80a0b3622487564a,
  0x1442ce3051d00595,  0x859bfd3c67ce1679,  0xf250a40d51bcf689,  0x72d489bfb019a722,
  0xd9f5cd2ed3e5555e,  0x5eb5b965f04c7f14,  0xd552916b367b7519,  0x2f972fffaedb0ce1,
  0x2f0d3cc89d7a50ea,  0x4b833a6ef407bb42,  0x7953a52ddd006bfb,  0x1976920a2394e8f7,
  0x89343df01d531dd2,  0xb3806d0c7ef87d47,  0x878f9af5aff621b2,  0x1dca82c1b7c0cbac,
  0x8334126066399b2f,  0xbc6565ebe2ddd476,  0x8e804a39e13d466a,  0x51e9853bd3ec027b,
  0x71d0f1492bcf9e47,  0x8f6cc79cca688a63,  0x2f58619c4b6ec204,  0x11b2b2663924d73b,
  0x143a5431821a18ce,  0xcc91ceff468ec896,  0xbb8343be34fac7d5,  0x0afa91a4aff123d5,
  0x9d26ee1d3d200938,  0x51bfe5a108cf3cf2,  0xbdbb91ff04119bd2,  0xbe06f657a564bd7a,
  0xff98b0ddf0a33534,  0xe9658e63cc30f61c,  0xa7272e12ef2f8632,  0xa6cb70ce149cabc7,
  0x59c88e815ec621d2,  0x425b0613e222492d,  0x5e920e0cf8efda50,  0x11c8dae17d6ce1b7,
  0x469fe1e3df45b8eb,  0x3c46c087f32e5b7c,  0x31090591a2c9d60d,  0xde3859582f794257,
  0x9a0d6d3d0dd651e1,  0x233a148ce147534c,  0x81169806c9cf5b60,  0xc16e1240b09e9dc4,
  0x5f17f7a0a955de27,  0x83922abe2f35b457,  0x41654ea34a1fb7a3,  0x2dac05e37e5859f7,
  0x0f917234c87b2515,  0x6335aed916a2e66e,  0x632530dd275fcd03,  0x21de9b7637b49044,
  0x62379c53cb21bd12,  0x58701683c2eb0a66,  0x207b95a638110f4f,  0x605deae1ec132643,
  0x1440a561b05187ed,  0x60709e5e9c7e6b35,  0x98f5afdde1b328a2,  0x6c8c908506001fc0,
  0x3301c10882ccdf17,  0x19d1a6efc126a20a,  0x8a6424c570f0d675,  0xf2fc19d1fc23f19a,
  0xb96a23fdcc5d7c69,  0x1c832a8f8a49cccd,  0xbfe9a8e355a44490,  0x5ebe8f6aa8da96b3,
  0xb5aba58b531317eb,  0x808ad3c2a41f21ad,  0xd7ad25d005102681,  0xd2badeff378921f7,
  0xe978bc60b156341e,  0x6a40fa5ec8467586,  0x02c4e307ef91ef59,  0x882bdd2d6b734014,
  0x014d24d62e924d68,  0x064b3f6f5f87727f,  0x082a2c84e00ceda5,  0x05b6d038076ed6d9,
  0xdaf8dd17fd46c690,  0xcd3c26d397b64f62,  0xbb30fb4babcabb38,  0x0f79828b828f505e,
  0x75314d61245ff5ee,  0x9505f5ac578ea40d,  0x950f64600ef052bd,  0x4446a5776ca6727f,
  0x6c1ec2e81ca84995,  0x8b50b067c5b04b3a,  0x3d479792bf614ba9,  0x3044a30f9218647f,
  0x4e19c79f322cbd16,  0x094aa291fe408b4e,  0xd5fc68bb8d868bba,  0x01ddb94d6d026855,
  0xdabc72d9dda22fab,  0x76c2be9f33b5e354,  0xc244f14a4891af0f,  0x5ff393dce6b9a695,
  0x553ecdb1ea547a02,  0x56d840db20a81604,  0xd8c165a6f8b70693,  0x80609f0604f6de16,
  0x8eb9dd8ab2feb0af,  0x1b7994d91a227415,  0x01ec1d12f652080d,  0x01d30c24ffa4e8c0,
  0xd7a72e6de6e05f3c,  0x41b08f8e92c4f92a,  0xcdada2cf7e05b596,  0xc86a8fb97270b42b,
  0xee383776b9e10039,  0x63a6e1827759890f,  0xca0b02619d67750c,  0xf0626486a0a00c49,
  0x4d7b2050e0e6d58f,  0xb3f7cf2ea1c3efd6,  0xd3df55a9b5a5f847,  0x032988d3dd7715f5,
  0x00a68280fc923f03,  0xde5c9dee565b3b70,  0x21dda54c5c3af94b,  0xf82d1eb932f8309b,
  0xc64959eecc211c27,  0x9e3c3eeeb1f83d87,  0x7bfdf167e12bde7d,  0x447aee5e93170707,
  0xd80062fd7cba24cf,  0xab4d1ca31a4a4f20,  0x78c2a4e30095e9ea,  0x7d1464172b7e55e8,
  0x19cb4c9aea3c2ef0,  0xa9ce3f2928eacf87,  0x3db6c20f556e9a77,  0xe45166f0edb370da,
  0x49722e218717c1d2,  0x3f859d48a20030e4,  0x44cee7cb6d1c738f,  0x0840ca09e9289322,
  0x1a3d9d0533ed21a4,  0x0e8112efebef7bcd,  0x900a77abef74faa6,  0xa013d3a5187b1760,
  0xcdb6f10f1c245212,  0xc5ccb743a46a89cc,  0x01568d08fc1af57e,  0x585faed3ed18e3a7,
  0xac050a8a7553ef9e,  0xd275e46ce694662a,  0x8d9e866197f71863,  0x213fad426f72153c,
  0x444a28ddbace45ff,  0x79df99c672a4440a,  0x7c0b8a3196079341,  0xbb819833f423773a,
  0x95dddc6a6a83b10a,  0x34889032cc910f7a,  0xafdc53695f209003,  0x522ee2be765dfb46,
  0x936c3c87e2ad035e,  0xc45276d58bfb5c44,  0x26e8e42d42ba00f0,  0xff0cc97e90d842a3,
  0xe8598c5a6d1a256e,  0xa33dc267b6131147,  0x7a8e3e7753dda9ff,  0xe4aaefee8f7da3f3
 },
 {
  0xb03ce75010608c29,  0x69b08cdee0c0e76e,  0xd5acc602670276f5,  0x73d823404de3e4a3,
  0x71a6318c14124d41,  0xe6e95381ca002294,  0x241276d748bac4ec,  0x31a22eab426168ae,
  0xe1641ab8073297b1,  0x04ce863f5708d7ad,  0xce31f3b378750f02,  0x46a0f368bc184488,
  0xe20d98b792ebe58d,  0x394f2d7194061232,  0xea691d0d8fb11d5b,  0x8730b77608c3a74c,
  0xe0f1ccff57aba69a,  0xb62786fbd7bd9b2d,  0xeebe3faed2d1acab,  0x4735ababb7efbb38,
  0xf51f2547e4230e24,  0xa00a5b343d100bed,  0xe0ada6b2623c5fa4,  0x4f043e16cde76247,
  0x43df84df61d266fe,  0xd1e49b880e8eb97e,  0xbeccc395f92a22d4,  0x7a4d0e65176a61bf,
  0xcd6d1fed9d22216d,  0x1e65411d6a1a6660,  0x96d59a508183b87d,  0xc91f88496efa4f03,
  0x9d2e34a1267ff756,  0xd2a6cfe33fc085da,  0x77114447a87e9e32,  0xd5132a7c307468a1,
  0x1e03e08a34b09591,  0x31959ba631264b8d,  0x53db958dfc2fe113,  0x38b8e262b7d5927d,
  0x752329460185e58b,  0x0ffbee1af88c3d80,  0xad2e2ced31fdc4ef,  0x2adb3a0615c39ac7,
  0x001cb7c2e092a318,  0x9d1c4d64afd15110,  0x74718eec7d40b72f,  0xdebf55043ae2bd8d,
  0xcbcb46bfe55d4d89,  0x1a72d12125147298,  0x46f3f8c38f92a234,  0xd5eb2df53770d9c6,
  0xcae33bd2b42be156,  0xf233811674c906f8,  0x7c731bd852a30c64,  0x4719e18562a54216,
  0x4d971ce30d7af0e5,  0x911b095636b11bb7,  0x2e384bf40fbd64e0,  0x3bca04adf46307b9,
  0xdc498788e0b7e1cf,  0x9153e1917ec5cbb5,  0xfe1bebb9379d6172,  0x00ef1d6d07a3fdee,
  0x8a5ab0961e045bdc,  0x43939132113e582e,  0x1c2d2ee4ed04a6f3,  0x29933d94377184a8,
  0xc99ecb42003e88aa,  0x5563071a55097f82,  0x9f5e9d50b0031318,  0x3e3faadcfe763717,
  0x418f35be401af6da,  0x9903be528e4d8517,  0x8f88b4ccf362b7a4,  0x3e4ced84d1c4f295,
  0x9fdcc6b43f163149,  0x8756ed1268dd8396,  0xdd79049019b68f26,  0xfb44cf3e787855f2,
  0xee85f38aad5e3ae2,  0xb611184886bb7fd0,  0xe7bdd55f5eeee894,  0x080afd5c3c3a8b41,
  0x90293fdedd06628e,  0xce27037976acd200,  0xa0bbf6a44a5cc5c1,  0x8a31e4a49ddec30e,
  0x265ad8bf4ec68372,  0x9ebec334d2189406,  0x62fd6ff5f4460f80,  0xf4eb895611661e2d,
  0x745cd31a0425bd95,  0x884ab67be1379b4c,  0x79a58bba30b32766,  0x7d739bfd6900b5b6,
  0x9fead3182a022f5a,  0x8018c9d0e59b7049,  0xe461bda8b3a2792d,  0x988505b67b434958,
  0x249a1e151db77fe3,  0x093facd824bbdbeb,  0xb7d48cbd7808f845,  0x1c338ef120259bf1,
  0x06e993552f7e6954,  0x1cdaa7e8a3db57f9,  0x173856c66b37facc,  0x3eeb4e366fcd58ab,
  0x5b65e3984c527329,  0x25ebe2ad9930682a,  0x3914502e5c1d69e3,  0x3dc8d8ffec9015ed,
  0xbf8e4ce63500b53e,  0x16d0bb67b4f58546,  0xf429a629944dc6e7,  0x78e93a6baa8a956e,
  0xb885b5ffa39e078f,  0xde42d4477f355115,  0x62d3b163370ed6b0,  0x852859f858667191,
  0x79820d20153156a8,  0xd2b86432a73783ca,  0xc1f8962c5c622006,  0x671f6319a537de3b,
  0x137b017f584b2159,  0x78bec9e9e134f8a6,  0xda5730245c8cb5d0,  0xe882e3ecd713b161,
  0x8a08364a38e2e626,  0xf6be57c187fe2770,  0xc857c6ab323f05ef,  0xd7674c2705dc5f64,
  0x180c108ac260b8db,  0x6d084e8079bebb33,  0x10fae1022ab87222,  0x52b0d112abca6798,
  0x2d1ce2c256921841,  0xb503a3c473324ce0,  0x01d3b22d6facddf1,  0xec3f7d4b81a751b6,
  0x795fda79e1609ff3,  0x71a32d33ec049ece,  0x5b3ecd0ec54cb685,  0x69665c59d24438fb,
  0x5a58470f4d892ddb,  0x30c62f3249520793,  0x833654be3d8a4792,  0x4b4f4fc876654f69,
  0xe7f59dd1fb52248a,  0xe1a1382ae31c3684,  0x386b0657642610b1,  0x114e5f5fbf58ffe8,
  0x1534d00e601296b2,  0x44830d7c5784ab7f,  0x5ca7bc164f25cb86,  0x5852ddeff16af3c0,
  0x8034c31f01dcd139,  0xdb6207b054a270d9,  0xc5b169450f34e955,  0xcdd9324b0e308829,
  0xe0d1f9fb04b191e5,  0x150dbde12f99c061,  0x54fbb3193baab1e2,  0x8d71c5ab1898f262,
  0xe1e03194bd670e2d,  0x194c735812883217,  0x773429649207f849,  0xd441a4a633744003,
  0x35176fa3c72bba79,  0xe4d0f71287d66537,  0x509c40e08f0dffaa,  0x5aa97c8269b59a84,
  0x926ce8211e425b24,  0x60e0cb1b3c9e3710,  0xf570d0f47919a959,  0xb5e7a5151de87d43,
  0x4a7a9fddf2a192db,  0xdf20aa5f8b96acd5,  0x9245780ecb829dc1,  0x855d7325013ee349,
  0xf755885e0b6302cb,  0xf87b48e0a6c36f72,  0xe446687da4411aa4,  0xcdfa3ba0894b4756,
  0xeb16549034ba10db,  0x6f029011723e3d62,  0x081c132848b4b065,  0xcad728e85b7996f0,
  0xc52d1c172f13279a,  0xb51fb6c477d4787d,  0x7a2d77e6a921429b,  0xb1e0d2c499ceb686,
  0xf157f0ecb1c1d091,  0x00feccc3462552e3,  0xc4429b79b8203364,  0xbde11d2c4602903e,
  0xb9a21b2eb7964329,  0x490a46dca5088add,  0x5b7ee0b9da8fdab0,  0x1b0200cecfdb5166,
  0xd4abfcc7a0c10914,  0x7fb33d9413f25fc7,  0x171f798ee6ef7a33,  0x3426901fdac125a9,
  0xa50713a6292eff9e,  0x045d4bd50afc7ed4,  0xa140e5133c24ce74,  0x24357d543217200c,
  0x2e60a8bd7413fee1,  0xf33b0bc6bb3bbc94,  0x432f5935f4fea2ef,  0xa8a6a292bfcdfe22,
  0x3d43571910854fe6,  0xc59e4a7204eb6751,  0x0ef3298c7798ca31,  0x98bbc5ce17c25bc1,
  0x2cb17f705a0365fb,  0xe11e6664cc135192,  0xb0056c0f3d8d729b,  0x93d7d9e01e450435,
  0x932fad7d4dc5e615,  0x6e997e44af9739ea,  0x442746b9c11ec600,  0x0e70d9460796b55c,
  0x87d238d617c07aef,  0x581fc7de9bb931ce,  0xb8921e789476abe8,  0x04ed6a5a0c695140,
  0x6d82e7f1345c1484,  0x2448e4caaae239e6,  0x344e50b2f8cfa53c,  0x0d476b98b9cf39ff,
  0x1032ae03839b38cc,  0xf6438d8a2513963a,  0xd518f679c34651ba,  0xaec2f889906a9f20,
  0x2e6ff9b0fb5df1cd,  0xe8ed6c8789db6dd2,  0x16a6f5ac976cbb20,  0x3b52e66184821bf4,
  0xe8025ade667369c4,  0xe7a8718af5dac8d4,  0x2442f9e63a34392e,  0xb7deb4bc266ff493,
  0xbda53a360f93d293,  0xc1a9352e4033f9d1,  0x78d72b150079f32d,  0x2cffef85d9f98b4d,
  0x9d0bd62f83e646bb,  0xc696f1df53c397a8,  0x47099482ac080a5d,  0x1c3ee173a330e244,
  0x636cfa99a6bd51fd,  0xf20fe85effeb000f,  0xb45a727bdf166c61,  0xa19d363e103a048f
 },
 {
  0x3b8d31b32816c747,  0x2017a177361f48fe,  0xbe472f12f41e184f,  0x1b08ef3368eb4d19,
  0x4b32b669a8bab235,  0x8e66feab60447354,  0xcd59d43ab0aee068,  0xaec9d69eda4470ae,
  0xee87ae6791dca082,  0x1b58da0745022c7f,  0xbc72cbe1f5346f8f,  0xb1d5ff32c4ad27ed,
  0x38d5dbb794615160,  0xd5a8f239829b61b1,  0x036ed7d071a4e4c3,  0xf8ccf8bd4526611f,
  0x3516d4bb752473b8,  0x9337da02ce66fd24,  0x27fe9d9ef83dd33f,  0x069b627899642f4b,
  0x74ba8512e9c0b528,  0x9a6f1813b0427e1e,  0xa2926343587bb374,  0x31e04f5d2c032fe1,
  0x8346c13411c1ff22,  0x2bfbe7f0435c5ee9,  0x88394a207f386857,  0xebc4a012efa64fca,
  0x27a31f39d02496b9,  0x7975508914ae7898,  0x6d6d051214c5b88d,  0x2889f7920a7b0b43,
  0x9ce024b09424646b,  0xa9a09b01da20b3d1,  0x893970b126cc441f,  0xe5bc744e87e77a2b,
  0x536c63f2cc991f64,  0xff3fa71fb5a8e875,  0x5e10aaeb7e402e53,  0x3b65177c3f2b27ce,
  0x34d550edcaa57d11,  0x654cef352412d05a,  0xc6e32c6b8db33794,  0x707765f56874dced,
  0xfafb10cf4e165231,  0xb62ab59aef63d6aa,  0x36812b0bf0560df9,  0x649397c6c98df4ae,
  0xdc7b867ef62bda1a,  0x9f67fead8a9a2412,  0xc1e633fad3d8919e,  0xe9332c4c10089282,
  0xc3541400894e4b5e,  0x4535a6e95cd013c5,  0xaa0afe5650666c84,  0xbed7e058ebc25bb6,
  0x5ec76b518fe71b3e,  0xd51b44ce026827ae,  0x4068e396f11a37a7,  0x18bb0bdaf6d4dbb8,
  0xb91ebec3bbd8cd92,  0xd1c8291d713f43d6,  0x6fc1db3acb1f1316,  0x3eb5adc44e914751,
  0x8772b5de5f48c9ba,  0x68181d08f2483add,  0xbd68a6dcdcbd835d,  0x78023b9924f0246f,
  0x1d9da511dc586f62,  0x2d8940d998287fad,  0xfbb0dc17834abdda,  0x3db182d37ecf0a89,
  0xa9a7edce45b37879,  0xf5ce683647adeede,  0xbd2c050f8e60c640,  0xa27e7fce7e60ff64,
  0x8d67688846a58632,  0xfd7911398671364f,  0x68e643b53ee921ae,  0x54689eeb81fb67ac,
  0xc0a756b9b2d7fdb9,  0x3f72c61dabb70940,  0xd356c9ca15b18611,  0x6e329249cec1678f,
  0x5b3886bcc2cb0381,  0xd2e6cba982b67343,  0x2eba2e96b564bf03,  0x2364681eeee92d7d,
  0x5d26f04715d0223b,  0x28faa523ca31580e,  0x5e4cd59532591e04,  0x912a78fb1fb6072b,
  0x50ea4f02662697f3,  0x331a954ae1040e47,  0xfbb4d50f53ee4818,  0x699567737948a2e6,
  0x3bc6fdd2f973eb00,  0xfcc7b40098bfb9a4,  0xf858f1088bb53159,  0xfc37e901765998c2,
  0x68a7af7b0d530b01,  0xdf1f1616159dd586,  0x093f9e9a5f9497c0,  0xc674187c19e799db,
  0x9bed2beedb1ebf20,  0x145df7c3cb414d6d,  0x0401e2ffd25b8ed3,  0x4ffcde171203e0ba,
  0xd3ce6b003c4bf92d,  0xb58c86c85962b95b,  0x7067bc00b4d60dd4,  0xa1ad8d3c215c4bb6,
  0x12b19b745deb74ff,  0x0350f2542f22df04,  0x90abd1a79874b5f6,  0xc0af1bb753c8f46e,
  0x942c4b6af1968d9f,  0x2e2975401f1831d0,  0x8061233d925bf5f1,  0x3b6cd089a00e0289,
  0xb56290018fa846db,  0xa90bc33c47451f88,  0xe7553ed02495aeaa,  0xa8c9803bcf575aad,
  0x9e64491e9060904f,  0x60d3eaa589a4708e,  0x5ad838d7af865d41,  0x6a3ee6d6a7da76fb,
  0x33b52a134b0fbcb7,  0x5dcd82ec53f10473,  0xf0ca2496da662420,  0x4a80b68cc3691999,
  0x924bede74dcafed6,  0x727c43d27e94f51f,  0xabcfa581eb051550,  0xe32f49c32f6e586c,
  0xe8f7dab469c7e476,  0xb82b896a99894c28,  0xcc8ca5feb0f4135f,  0xa6ed7c9263e4f957,
  0x1862b1e3d1a6df64,  0x99fa4d8485d93bdf,  0x220ac23640c25a29,  0x405da9c3ac837c14,
  0x7ca204635c8b6cd9,  0xd0272f71cfc14fc6,  0x7fbac51d228e3d5b,  0x46517526bd898f3b,
  0x14a9108142f65441,  0xad5ea46885ca54fb,  0xfa51d376c6555dcc,  0x9d6c76783f03ea0c,
  0x23bfc85c63efe8c7,  0x912fb38813cb1307,  0xa0c5561ae732dc63,  0xd116b30a5708362d,
  0xb9d6d43f0f4a5184,  0xc6bce7431a734006,  0x380e1353fd9c258a,  0xaa22201496fa290a,
  0x4522cd97fc8b4f5e,  0xae01c057ba0c4f76,  0x3c1762f5564a89df,  0x4fa49c95063804c4,
  0xa4f9d71f7824e574,  0x70e7dc5d12bd4208,  0x33564151747bc6c0,  0x7a6c10f47765804f,
  0x864748831ab5bed8,  0xa7f7d8c16e090a92,  0xeb39d8872f011801,  0x57eff7c95ffd6ef2,
  0x055f89ccf96291cb,  0xd0e81bb73fc138c4,  0xaf525f2537232f9e,  0xdbb586b4e11a5edf,
  0x7bb605d5a6ec3f39,  0xbceac82c5c419eb0,  0x48c5c7bfc9ca8a79,  0x5820a07a25b1446a,
  0x6d7626cbab6f1581,  0x5ff57eb4f1670181,  0x2de608e1907438b1,  0xdeb958046eb128be,
  0x3d9c26c8eb155167,  0x631fed00235f8ea5,  0x35454fa079811a89,  0x1bd2fe3bbd8deecf,
  0xeda0317b9b190cdf,  0xe667f2f861bde219,  0x24ce84a5036e9956,  0xa829027c0f9257c7,
  0x1ef499910f3241b3,  0x141052f07962d3d9,  0xcf631d984c469a50,  0x179b618a18b98306,
  0x1e808f09cd0a3438,  0x0d4144b8b54a054d,  0x885d1a0178cf41cf,  0xeabd004cf67d811c,
  0x82f7293314d2f1ed,  0xd7bbbc3042764ff2,  0xe331b7959e6ea0c7,  0x6cfbeb7df34d5d44,
  0x7c00ed514a4d3f9e,  0x19313a31dea99ddd,  0x9d90a9f43ed1c593,  0x8018fd357142d1dc,
  0xfbac62e2d78c1651,  0x4af96c3ae4955550,  0x2e6cbe24eb7bbd04,  0xa3da07efacdd5ad0,
  0xbe12a32cf1f68bce,  0xc13f08f7d1db2c8f,  0xb4bb99a195c9b8a6,  0xa3ce429514921baa,
  0x3d600cb975dfb748,  0x9ca3e06c62e61835,  0x7633cdf7bc6eec76,  0x50d4021b1ebec61c,
  0x042a0c7da72d1dba,  0xeb98ff42b9e8a222,  0x4ca3fdb33b90dfdc,  0x173b7c027dc7d63f,
  0xab234f0bbb8e2286,  0xb26a2b853d2636cd,  0xb769bb868d1f2c40,  0x171093b556ddccf6,
  0xc5ccf9b27d3c6ffd,  0x0919dd473d2c9dce,  0xf587a16b5482074a,  0xc9c0be9c741b5913,
  0x8b71f7a6ddeb5fb8,  0xe2c037cde4ad1b1c,  0xd85510b8d501da37,  0x582465d5652a1178,
  0xdd3a9c1113808734,  0x6832b2af16a97340,  0x1d0b69fd51611db2,  0xda4b4d7600c9a121,
  0x6c728609439e1d1b,  0xfeeca2cb4860d907,  0xbfe987f30686f5fe,  0xed2ac77eb040e4f3,
  0xe16e999a15b450bb,  0xe4380a4435bf4b5d,  0x1faa8f7e94df22db,  0xd59a04bcae309d9e,
  0xf40fab3b7e6d8477,  0x6e23f724af15267d,  0xc8b260612fa566ab,  0x568ce1f089d0d5f3,
  0x96d33eef598f08f3,  0x41fa8fed7aff2e04,  0xdff615f9ec4fd955,  0x82a51616c070a2aa
 },
 {
  0x5c284f905ef849cc,  0xfb33560b2e1290bb,  0x658cd5b3cf9b2d9c,  0x58c69fd0ccc82b33,
  0x6cfd57ce25fb42a7,  0xc1e67ec1b7f2b700,  0x67ec5b3be679fa8c,  0x062b163c990c352c,
  0x23969eb8a67f49ec,  0x25fdcd2691677c5e,  0x76f19d8c97c32e4f,  0x0b1f3a5e9daf634a,
  0xd13afe061e619a65,  0x9100adcfa37455d3,  0x2ff505c615e36eb8,  0x5c627d2192f34658,
  0x19d099bd3d37f1c6,  0x98c44fc2d6882676,  0x62ad3c980a422c2a,  0x2e38ebe24cfd1707,
  0x2ea0240ad2df62a8,  0xc56744c5e7bfb11c,  0x22892820ec6bb1c4,  0xb3f6e1da26047d85,
  0xc0f927c8380e6f18,  0x30550ae6c0b32941,  0xc97b6444f8e1195a,  0xfd81c56c4e362423,
  0xd93b22c88ea95385,  0xc58b7d10ac5595dc,  0x7c9efa229c0c13f1,  0xfabcabb6130fdb13,
  0x0db00aede8116d3f,  0xe502691c15d57122,  0x156ca456973fed2b,  0x80064085914bb945,
  0xd407c963c6c2abaf,  0x8c62fc3353ec00c1,  0xe5e4c91644677be4,  0xe5314fc7a4051657,
  0x26b76d0e957b9fdc,  0xa11fcfd679c66f12,  0x4a78730d56033ad7,  0x417ff4b6262ec1ba,
  0x188f278c9586bd02,  0xdf6d11ade821b42b,  0x8e10270ef114ab99,  0xed5da7eca7165861,
  0xed32a5cc1a514558,  0x3fbbd3358854d658,  0xbefe1574b99946b5,  0x0a8fd5178de30acb,
  0x131ef0b46812983e,  0x14246cc94982fc0b,  0x73f11b5df8ca0b74,  0x93a08031877f97dc,
  0x308e9b5f08d18e33,  0xb20b73a9fd4b045f,  0xa4cd935e201b3ab0,  0xa9917c4404b07a7c,
  0x35cbaa3b1d4fc6e9,  0x81f146c9956ec4eb,  0x0a2abfec358af262,  0x1fb414b1397a0de1,
  0x118476bdc7c142cd,  0x2572c6d7fee6d041,  0xc77c96c3205d128d,  0x2fd2a68e56473e14,
  0x9c8042fa1c966b2d,  0x1f38104726fb39ff,  0xc8401ae0409d9eaf,  0x1ae68e5c02de2bcd,
  0x9147da494c7e509d,  0x3bdc522a39f478a9,  0xbeae4727f607a35b,  0x9d2cc46d3d79895a,
  0x818e11b0955f2bc6,  0x8d14df2ec860857f,  0x36559d9765072d05,  0x9aa1da6570edc5f1,
  0x87fe7ebb4c62d33d,  0x1e5693f0b4651fff,  0x0f6f53ad27fdd74c,  0xa398c48ef25646e4,
  0x090b3dbcf8de1967,  0x0312e75c8368c81c,  0x37f88ea822a5ff9a,  0x4db4ed7b67a34b3c,
  0x367641294f3c8615,  0x52ef51abcef690f5,  0x7edfeab038af04f3,  0x363344b5a17d6bf9,
  0x32dec47b836ae374,  0xb27384e05c56b7a3,  0x88002eb4ee3723a2,  0x87e6a6f32f34a01a,
  0x606d4aa34c3798aa,  0x740529c8f4632433,  0x4d3cbe434a240e7b,  0xb5f3edc745eefc7c,
  0xc30187915f084bbd,  0xde713f17f16caf20,  0x3ad749b24d08519b,  0x921452ce6555648c,
  0x5bf7a1fc26878ada,  0x0906e4a3a722e060,  0x571ec36f22ceacc1,  0x2f08c0af9e18a2ef,
  0x22223fc6d31587c6,  0x4bd1fa19b94afab3,  0xd6d1f9cf853c2e08,  0x8c5b769b88b4533f,
  0x51f269df4d312ed7,  0x9e2ebddbf6334c65,  0xb006677e70d8bed0,  0x121ee2a459c93e67,
  0x4abe2621fdd71111,  0x4a95840642566b10,  0x83af2d919f225a14,  0xa66781a2973cf882,
  0x105be71bb6fb2b54,  0xde56fefe9125510a,  0xc2443f0f8bd64e3a,  0x9e2a4b043b0e7f86,
  0x3437a1a5f57ceef3,  0xd2062686638e1de8,  0x7ce974fb977145b1,  0x9ca387242309a50b,
  0xfe357cd9edb05b51,  0x227c9442dcc73379,  0x1f32043ce785de92,  0x96fa171fe6a68b2d,
  0xadda8039d91e7d80,  0x2b554b119667832a,  0x9ef3867329a1c88d,  0xb61e470b115f4f73,
  0xe42f8d946f40bbf1,  0x1e6dad97f634ab8f,  0x19b509854677c8e0,  0x799667eefc2ba2c2,
  0x136f80839d7b0846,  0xa1ea5cd23b01b200,  0x2a6fd9bb4bdb03e0,  0xc7ff32edee5f1b7e,
  0xd61a01141d04ee01,  0x2ff1f83cc4d595e9,  0xa6fd07357504ff5c,  0x2d2f143e99bd101f,
  0x7a831d66574423ac,  0x1bc3bc9c082924c4,  0xa3825d43899a16a8,  0xa5ff2bf145d239fb,
  0x38187666d83c63b4,  0x4eeca9f2759b6387,  0x130123351835a97b,  0x6d9f4b2b20725d32,
  0xcce200fc1e62d49d,  0x74aa52380f21590e,  0x65cc3df4604d24b9,  0xf1687cd8770a3a54,
  0x31c75d90452bb7f7,  0x89ecee5b813334ee,  0x07bc5f2ddb137380,  0x0ec6e6611dc24aa1,
  0x5a094da12d6d51ac,  0x6f85e698381c676c,  0x74064428aa64453c,  0x1f8ef874a3fc916a,
  0x9b8167bc3d01d4bf,  0x43d10d538e931261,  0xc89029dee01edc1b,  0xe4c34fa567ce7b16,
  0x62137dad120ec797,  0x22d7434a2250c015,  0xeeeb414caea5d1e3,  0x14a49a900ae89202,
  0x21f98a79930c5862,  0xafd208747f965766,  0x2645c0c42b6aa9da,  0xfd9460f842363cc0,
  0xf3b5cea83955c1c5,  0x65dfb9a4757db3f8,  0xc64607ea3962cf6e,  0xdc2a0753d3f581a3,
  0x978c2cf696eed634,  0xbff4bdbaa66bbe8f,  0xf0df921d953aab6c,  0x24eeb3b492b57ad6,
  0x91ae74160a977d5e,  0x6dcb276254a304ed,  0x9092378218c88f2c,  0xb2c5adc76ec6be12,
  0x94253f4b48c80421,  0xbb6d1c99c63c8eeb,  0xf1b4641d7bf9238e,  0xe66e95c2f32a724f,
  0x1baeb631cdfddae9,  0x12c15f453a593a1c,  0xa50071c02de2ab02,  0x4c44f5cd54cf555f,
  0x25d5533b9b8139bf,  0xda7175ad515c05b5,  0x5f234132e37b8ad5,  0x560b87f0c90c385a,
  0x8c7460ce03f6f9de,  0x791d27461fef04af,  0xaeae2f4c04103879,  0x3b7978d35697f3b2,
  0xe025a9700a0569ce,  0x943f482e26087d08,  0x95f96f106e601514,  0x23a3f5afd680eea3,
  0x37d3862a13c70a9f,  0xaf2131b5db646bd0,  0x7b8f10fe00234365,  0xc60632eae3e73552,
  0x51441af02aec79da,  0x024cbe8328e32daa,  0x15749e6540d285c6,  0x50ab722aba1af40b,
  0xe2539bf72fe3397d,  0xd6844a0b0be2877b,  0x69601b2ddd04db30,  0x6ac0e8651916f0ec,
  0xaca5148b85ec22c4,  0xeccdb79e4210b3f1,  0x291df3ecdcddc185,  0x23cec666d17f843d,
  0x33ac6894cd6d3464,  0x99b33db3bc4ab6f3,  0x77b2239e5752cb0c,  0x51c7e5e4fa37c6f8,
  0xa16c0ba4048f7c84,  0xc6dff106139dc869,  0x03d86e39b67b76b4,  0xcd4a9100f9a30be2,
  0x70233f72009b9e16,  0x2932bc77efce2e22,  0x88ae5974051832a8,  0xe352dd678ae8be0e,
  0x80f60725b05fe8fb,  0x58241071a4f834bc,  0xba7d3adf19be5da9,  0x35bb5f678eddb6e0,
  0xa1ea3f1b5fd90921,  0x0ab101cdb38b2781,  0xd6f2ea4fdffc20d7,  0x91ad27d1aa2946f5,
  0x3129fa02100ea29f,  0xb0f77676d017261e,  0x9c15435083ab7294,  0xac28dd3c20907036,
  0x31fa9d1c3146839d,  0xdbcf30c45a71afaa,  0x939a2519141baea9,  0xcaebdcffb093af84
 },
 {
  0xca3ffdaa139a352f,  0xdd99633e7cc0b424,  0x6a916a599daec87a,  0x74962fc2f85201f5,
  0x5d4a4ca57937ca9e,  0x4846d5490b62cab0,  0xca4091d0e431b6d4,  0xc32956355d88d253,
  0x723cc1357ce0ec4c,  0x5bf5bd977030ca95,  0x74c2ed3b5c5caefb,  0xd52237a6011c1240,
  0xac94055013d9546f,  0xab5f5fc987ac88c2,  0x0630d1c1fe055d82,  0xc7d6009a93edd2ef,
  0xb66ea9b2c1a9bbd3,  0x39aaddb9a7a4a3ce,  0xb409cecf3c6d0171,  0xfb7904db5489fa1d,
  0x9e3cccf4fe36e7bd,  0x3394fd1f8389ec07,  0x16cbbbd192c54911,  0xa459ab5afea8b015,
  0x628894e560863041,  0xddfd9155e4c7347d,  0xe86a7d1e4579ae0d,  0xfebf48f6a559a8aa,
  0xd6c6fc41c499870e,  0xe3b04cbc583daa62,  0x9a2f4bb6287fc2a3,  0xf767e3b9e8dde8dc,
  0x4ddcb2910c7a735f,  0x66193f978a5329d3,  0x32b209c392c5f139,  0x6b672a60ea38f131,
  0x2bada21894d928d7,  0x9325a2778c0f6899,  0xc8a93fc35c5d56f2,  0x079dd000b02f9d9e,
  0xf17de1797341847f,  0x1db1444c2d3bee30,  0x7c07ecec4553d2a3,  0xab8c5629177babf0,
  0x1f7dcaa25c489b2c,  0xdc2b729e212cd5c5,  0x418fa29eb0a88a91,  0x636bfe641c54188e,
  0xead225e010f1ad94,  0x14910289b6614192,  0x12ff55cf19f3ae21,  0xa6918621db3a7698,
  0x927fd7329b569d2e,  0x992c7552ad2c516f,  0x87bdcd9e59c79326,  0x3a2565ec22fed394,
  0x8ef17cbda6ff8758,  0x29b8e9b8b2115e77,  0x0d3b130a30e65812,  0x1564d92d4ea9be3a,
  0x2a1f3419e7b56671,  0xb02c8fb634dfd9a1,  0x94d8770548435cd2,  0x4a0c97d58ff5bb74,
  0x358c8a3d25b6bdf7,  0x057fba05cdf4a9ef,  0x95ba7d6eb0bf6336,  0x6987f2fb092c2bf3,
  0xdfd21a5b3fa59134,  0xcdd300f42c2c2108,  0xcaf6fe6954cb9e37,  0xd39cc403500d5233,
  0x5d7227336749e4fc,  0xa0726e5531cb9d1e,  0xf0e464f98e358b9a,  0x0097d855f19673e0,
  0x6040ca10071d7592,  0xc031451d4c4cc89a,  0xb62a7b379168eca7,  0xb57c1115b518c1da,
  0x8bfe5e5c076cd1ee,  0x23ffaf48123a82b0,  0x1dd5db18413e7166,  0x4f258e94e105f20d,
  0x9431b069834bf4a4,  0x24ffd3cebc64e368,  0x6d56ce9278c2c837,  0x2341c80baa525bce,
  0x5677ef0b70294b80,  0x4a09389ce1e43c37,  0x3eeed1bfef48cab5,  0x5d4786096690caba,
  0xe69b4be95119450a,  0x74ac871787b48aa4,  0xccca2c36f59b7ab6,  0x8b9ee777af8a843f,
  0xe39e629158305cd6,  0xeb1e1bbdbc2fe2a2,  0xddb7f820aae1fe81,  0xe6cc3fb2c2d83c52,
  0x2f18cd1e6fb56d43,  0x608bd88ab1829daf,  0xc14c53054f5402be,  0x60cb03ef34a62bc4,
  0xed5cb7026234511c,  0xac1d8960b6245436,  0x81948ed57f59c421,  0x1735ab30d50a7509,
  0x7e3c001db9a25993,  0x6ecd6558f0b6d7b7,  0x386413ab49e1e43a,  0xa0577a6f965d139d,
  0x50110e94cb3ef964,  0x8c3c6ac92076e75f,  0x5e8f7f2ed14c6469,  0xb8f24b3352c40e8b,
  0xf194b3032c37c118,  0x8c2eeb8bb1852f12,  0x05a9861302ac801b,  0x9e2759e04a614d31,
  0x6dc96579055705c7,  0x1e8e16df9dd6bd03,  0xf684a958bdfdceca,  0x4cc45b74fdf668d2,
  0x12fd80eedf7e0d24,  0x94b9e29f16961e0b,  0xfd45ed63a3693d20,  0xa71a6049db72acf0,
  0x946a1bb972e64c56,  0xf799935830e4f554,  0x9e3a0cf2b92fb329,  0x2b6364cf3e112211,
  0x22133f5ede13685f,  0x7f11bd1bff15a243,  0xfba18d158ff4395d,  0x4f9bbf960d6570bc,
  0x07bd346de395638b,  0xd0d79cb303f06fa8,  0xca1bdc2cdedfa563,  0x9c461efa26b87e49,
  0x54e00e0178525f2b,  0x2426e158e0fdc11b,  0x1f6f91c0481903cb,  0x507a53ea0df2f13a,
  0xae6866a2d2e2f681,  0x12df0b016bc70fd1,  0x4b0e5efa523bafed,  0x6e56c923b33be5b5,
  0x4d29c5e281a58f8c,  0xc3351fc4fee27984,  0x3960f83903d0089a,  0xa39edc7d9a4bf1a2,
  0x8a3193d428aa69a9,  0x13b0a508857c4865,  0x5de56f39a59a7b8d,  0x70afad1f43caac73,
  0xe0ecac67e50d9982,  0x935c6ffb56764f9a,  0x05e207a170b8fdae,  0x96fd0c8ec6fae6ac,
  0xb32e4e6af6560c82,  0x6191c48899de749f,  0x74b15294c2875a33,  0x1b790e88460ccb28,
  0x6d03946e58d440ca,  0x0d10e8af0290e257,  0x4171103c2fffc6b7,  0xf73893c3ee629689,
  0xe45a19e54b920365,  0x30970103682f0d7d,  0x8df88feeb0037d2b,  0xddcbcdec62a64cec,
  0xa5bbb71684fdda01,  0x11c385bf003b28d2,  0x2c8ffe0e45d005c2,  0xb8a1dceb87ebf32e,
  0x55ed693ff192e74c,  0x1a53a40f348d4c26,  0xdbedfd2b45d4c988,  0x4fc79ae28eec7a84,
  0xcf7afadda9d4d9ce,  0x3a50074989187ad0,  0x032eadec2afe1b62,  0xd11013efd4a086d0,
  0xe1a258db0644f561,  0x61380e8d6985f41b,  0x830b91daa13e879e,  0x2a4de89175a67dc4,
  0xb85c3dabe8cc1ea3,  0x99af2a7affa77bd2,  0xf5750bdce055ea8f,  0x9abd0039185d4cb6,
  0x0668c1d721e04cd3,  0x71c92e462a0215b3,  0x0ba4d83af9015a3d,  0xe784671d731781c6,
  0x317c4433090f8f78,  0x152d8cde518810c6,  0x559452fbd605cd57,  0x6eae79544120a7e9,
  0xba3f5f64e33dfaed,  0xd201fbc4c6972281,  0x38a29f5f1bf8bc98,  0xf50232af78bd2633,
  0xbe119976cba86dd4,  0x2d97cec2b9b9959e,  0xde1bbc2dc6b20ecb,  0x6c5316e9f0914e7c,
  0xe2fdf57b957a3d24,  0x27fe71cde09f8ed2,  0x937165eec938b874,  0x879e4d5124013bb7,
  0x6eac936bab1033a4,  0xd5c4b9d2fd09363e,  0xf0fd142a07bacd04,  0x81031fdb0c4f31f3,
  0xd9c5f4d2c596e5ce,  0xf24f226e3a45e6d3,  0xc1f40b63286d8425,  0x39c3531fdd887e78,
  0x09cb8b92e4188e16,  0x6d42aab82fabc1e1,  0xccb26199accaf7f2,  0x52fa7932543acbe6,
  0x662d2c25eccae157,  0xbe545c0779d19f5e,  0xee4b45a54cfeb3b9,  0x6859b6b9559784b2,
  0xf45029614d2f1eee,  0xfefec03c39a25d9d,  0xe473885a437caf97,  0x3c0987b047afd379,
  0xc4122e162f91f0f5,  0x66836a964f593075,  0x55a1a2d37902a06e,  0x119d5df608bf2d1e,
  0xe3cfbe1d30ca2e3d,  0x6b992c44f0d9293c,  0xc012c10d2b761802,  0xfe88c06ed6f33649,
  0x4144e733461e0229,  0x6074392e80d2db13,  0xd6e3cb23bfe06665,  0x4ba029a7314dd2ff,
  0x286bac4a95b38f36,  0x2b819fc819538a1c,  0x7f807b232ace17ea,  0xb59637f870f5f0d0,
  0xa3e1e5e122aa0926,  0x43a19550d3de319a,  0xa3be800c7f326f2a,  0xa63ebd900317a14b,
  0xfe6f39c9a29d4ae8,  0x559b8ceb39775fd9,  0x1246228fd295ae89,  0xfd6e5a61de826d4e
 },
 {
  0x994423f7650cef1d,  0x3bfa03f635762ffa,  0x2a534847f181b85c,  0x7ffcc6cde63348b9,
  0x2da6816a1a27e904,  0x8705b2db3f8ee3d4,  0x178f4e206327adf6,  0x6eacbd5bf24fe699,
  0x73dec8338188efa9,  0x8c4fbe0d9399a7d7,  0xd7f2346dbc3e1e1a,  0xa6c747d3fab5f23e,
  0x3df490de61390af9,  0xfb08b6076f753c52,  0x05cc7164dff55b18,  0xafd813ddf6dbb52b,
  0x1793d38ee3997b01,  0xaf7eac7046fbffdc,  0x1ad9dc9903191a42,  0x76ebd2ea79e8ce3f,
  0xe5517d34a5fbbbf9,  0x63d6b2b2903b100f,  0xff521e365bb22417,  0x7eff4fc31d373e41,
  0xb698c9a0ac59616d,  0x060dcbd6a068fcd3,  0x015fc39539bb8f3c,  0x937d2d2b4f02499f,
  0xbc412007b775fe7d,  0xfa621b4d4cf6a602,  0xd2fa2d7976cf53b3,  0x51ad37c8e53f97d2,
  0x20e006696a4b44ce,  0x18dfea12f7b884cd,  0x3a4921e837b99b93,  0x39f98eb93f64c0a6,
  0xb5806b41ea6367a3,  0x4f919e7e40274721,  0x5d19aef786ec8eba,  0x9ff260432ad6320e,
  0xc07d1bee2ea0ee4a,  0xbc37835d295ccf15,  0xe9bf01d1f8c7c612,  0xdafda659fbb178f5,
  0xfb832807d2d95f36,  0x94c4235d93fc3a4b,  0xe1bab15b9bf0cd82,  0x3f07388f06577b79,
  0x4e986caccfd33a48,  0xb8bbfd3f68eb543d,  0x68ecd676f12a1e40,  0xa7a128a5e44f9d0d,
  0x47a61f5d02567339,  0x8c99f3139c016072,  0xc843b0e720a3a6c1,  0x05b30559ff87bd4e,
  0xd81ec9158ae85e9c,  0x2979661b027cfee5,  0x0fe80c2357cd71f9,  0xb11a4efff707fd62,
  0x36e2d6729032be23,  0x1ec42a257f3d5106,  0x514b5c8cdd98f545,  0x69cc666693a4a245,
  0xfe857ac66a50584f,  0xb208b5fa2e52b5d8,  0xecc34a1b5815b7c5,  0x0f8d3e3f24582417,
  0x51b8a7b9afc4f712,  0xfde00bba256e6033,  0xcd0745dc0ef2c90d,  0x1fb2ff5d48158d83,
  0x8dd931f907b88be7,  0x57d8894d1794a12f,  0x9749b43a2e2b56a2,  0xbd66d37358e6413e,
  0xffee4677f02c1857,  0xb79c39c5debca0dc,  0x0762b9c807f76fa8,  0xdeb04a74875f2e0e,
  0x5d1ff9b04f5b26ee,  0x1002a28eb1611aa4,  0x20f947724e517084,  0xe4c065651e5f24be,
  0x41fdae693d493f45,  0xda050e3e46069521,  0x3f98442d62067d32,  0x8f7539122396437c,
  0x4b0d4111656d36c4,  0x7792b2500e34e453,  0x47bfa48eff4b1a89,  0x67dbc9ff2bba7d52,
  0x084edbe12b363cae,  0xd23c956f41cc63d5,  0xe018c691578e6fda,  0x708bbcf42a27f52e,
  0x67f225291f750d36,  0x7f62b096e5c9db53,  0x07ab7aa2dcd15795,  0x8c82a5f6980d90aa,
  0xd16f6e3dd980ad8f,  0x284798f3c1d8da24,  0xf015bf369dec4508,  0xa06d54093c7f5a29,
  0x5d262b0e391d180f,  0x4d40e3e40da98d2b,  0x38d8ff2f1c3b4605,  0x3459ffdbd4979a79,
  0x9a7103552f0aa6dc,  0x3576e86d4b657f67,  0x88ff0359be789f0a,  0x3f6394834a0180b7,
  0xfa401bbd952372f8,  0xc9c3abfaaac506c4,  0xa55a0766000174b2,  0x7df393bd65eb64b7,
  0x6ab0c2af6efc7bed,  0x12a457e165f743d3,  0x80b3b3431b37458a,  0x623c80b57ed3e307,
  0xf30cfe7c7e2bea55,  0x5eac1193e2d6dcf7,  0x96be769d2253b526,  0x7c2ff951cfe3be7d,
  0x4e0e0d2fd6bac8d5,  0xfae7d80822cdce72,  0x83513fa4796d080d,  0x099835c7c7cf8608,
  0xe0ca779d6d2f5308,  0xdb710606ed43ee1d,  0x5a5e81070a89dc85,  0x5e1b3fbec8ee9cf5,
  0x876e1a61ee264e77,  0x63c459cd14958a82,  0x2e49455dfe2defaf,  0x5ce1bce2096392dc,
  0xfc2016660bcac8f3,  0x5d54577be36b98fb,  0xa5b2872c237e2077,  0x620af42dbb08bdb9,
  0x788b08a4da3bacb6,  0xbf64ddbcb55b8448,  0xb2defb2949902278,  0x2153f9baa5b7ea79,
  0x0fc1d99a01946224,  0xe9f0e18947ddcc03,  0x77c5a617c4050937,  0xd913c7e849c375c0,
  0x1425c249fc4bd766,  0x9871b39337e6eec1,  0x7382ffbc3360a2b8,  0x0517513c6c4d07da,
  0x3abca6e8421d78ba,  0x5f0f220a24e94b44,  0x251a5ce0c39086e9,  0x285007667bdd2789,
  0x8f400d315a638991,  0x1a1ac5599e758b08,  0x140d5f7c689335e2,  0x968e83ebe7ba1ae0,
  0xe30ec5b7545c2fa8,  0xbece2120d2700d47,  0x3c522d8aaa70e69b,  0xcb153c82202f0934,
  0x78f312e3d178c44d,  0xcc65c10d5e001ca6,  0x3bb09d5d5edc2fd6,  0x0684f21f218f896b,
  0x86a15da99d236a69,  0x7170206d13595335,  0xf701a2bf30bf0223,  0xfced17aa52393aaa,
  0xcc1a678b5327a237,  0x63512c333296002a,  0x4f519d9f5982fa92,  0xe03242b70ae890cc,
  0x204b62d153658c15,  0xd570a6e451e90573,  0x0d5cf6203513c1c7,  0x743f056ca8a98afd,
  0x547276c8d0220f05,  0x930031ce4cfb22f4,  0xdfbf0eae91ed7b0f,  0x4d60ed069d767694,
  0x3d113395db82816a,  0xdb0e1bcf03245f65,  0xd4bba1449ff7e022,  0x6c7c06913a5a6464,
  0x21e44bab089b04c0,  0xa898ed19ccdc8e65,  0xa303268256674332,  0x9dabb09cd02c52d9,
  0x44ce9f40bb044525,  0x49029015f22bdedd,  0x8b1cda3a0c84afbe,  0xafd96cf0a8056dd8,
  0x80e814ee662ee646,  0x373415181c0818f6,  0x601337c5de989493,  0x841612e16f0f4eb4,
  0xd2c1d1dd2e808118,  0x6113b37b81c95594,  0x72c788a7099334d8,  0x0eccdbe2cf7e85aa,
  0xb78f93def9553f39,  0xddfea58add761055,  0xfe104ed3f8f6815a,  0x475667cdb1c1d47f,
  0x60193f537fb373cf,  0x1757c3e8cce4b9b9,  0x513ff2517dfb863a,  0x0a8010124dd7776e,
  0xbdfc89d4df14fe45,  0x044fc62c7109dc0c,  0x4b265a7e0dd5eb71,  0xbb3f35a3e16d0849,
  0xda77fcfc0affdf9f,  0xdee1803c4c1c4840,  0x7a8e562f0d82a00b,  0x132c10245ee24b90,
  0x097f49a62a6dc4ea,  0xe209a5848a30a460,  0x4b2005325706b4ef,  0x4f557e79e2903beb,
  0xbe61d742e13816b8,  0xa2db50d85bd560df,  0xcc79ddadfd7878d4,  0x113a3f110aa1dab3,
  0xf6aab848078f2e67,  0x3c2798b0c2e329b7,  0xec5a001e3e9f4c97,  0x3199ab573c90b359,
  0x3ef62d085c703268,  0xcd4ce8e5ffe9367a,  0xfbecfa96dcd3acea,  0xdf238e4a1ab4db0d,
  0x64c751c50f34fec2,  0x2ec5c5fca11920ac,  0xbdf5418cb90ba334,  0x5e9e9abf977e0495,
  0x506f102718f35315,  0xbb2eabadfd707b1d,  0x38f346deb77bb00c,  0x63d7fe2fe8fee078,
  0xa3fdd238dbfd200f,  0xfb678a0f265ed09c,  0x0c52bfd183ad7249,  0x5f1327fca2d1d3cc,
  0x4606992a91c75383,  0x2c18ee4d0ad845a5,  0xd2da1e204ae8854f,  0xc1f583311ef09381,
  0x2ad0879fd6f96de8,  0x3605fdda6d50808b,  0x483e5162a81ff2d8,  0x3a52ae569f9c7d3c
 }
};

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_clean( ak_xtsmac_ctx ctx,
                            ak_bckey authenticationKey, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  ak_uint64 lvector[6] = { 0, 0, 0, 0, 0, 0 };
  ak_uint8 liv[16] = { 0x35, 0xea, 0x16, 0xc4, 0x06, 0x36, 0x3a, 0x30,
                        0xbf, 0x0b, 0x2e, 0x69, 0x39, 0x92, 0xb5, 0x8f }; /* разложение числа pi,
                                                                           начиная с 100000 знака */
 if( authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");

 if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
 if( !iv_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using initial vector of zero length" );
 /* обнуляем необходимое */
  memset( ctx, 0, sizeof( struct xtsmac_ctx ));

 /* формируем значение gamma */
  memcpy( lvector, iv, ak_min( iv_size, 16 ));
  if(( error = ak_bckey_encrypt_cbc( authenticationKey, lvector,
                               ctx->gamma, sizeof( lvector ), liv, sizeof( liv ))) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect initialization of gamma values" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_next_gamma { \
            t[0] = ctx->gamma[0] >> 63; t[1] = ctx->gamma[1] >> 63; \
            ctx->gamma[0] <<= 1; ctx->gamma[1] <<= 1; \
            ctx->gamma[1] ^= t[0]; \
            if( t[1] ) ctx->gamma[0] ^= 0x87; \
         }

 #define ak_xtsmac_update_sum { \
            t[0] ^= ctx->gamma[2]; \
            v  = pitable[0][tb[ 0]]; \
            v ^= pitable[1][tb[ 1]]; \
            v ^= pitable[2][tb[ 2]]; \
            v ^= pitable[3][tb[ 3]]; \
            v ^= pitable[4][tb[ 4]]; \
            v ^= pitable[5][tb[ 5]]; \
            v ^= pitable[6][tb[ 6]]; \
            v ^= pitable[7][tb[ 7]]; \
            t[1] ^= v; \
            t[1] ^= ctx->gamma[3]; \
            v  = pitable[0][tb[ 8]]; \
            v ^= pitable[1][tb[ 9]]; \
            v ^= pitable[2][tb[10]]; \
            v ^= pitable[3][tb[11]]; \
            v ^= pitable[4][tb[12]]; \
            v ^= pitable[5][tb[13]]; \
            v ^= pitable[6][tb[14]]; \
            v ^= pitable[7][tb[15]]; \
            t[0] ^= v; \
            t[0] ^= ctx->gamma[4]; \
            v  = pitable[0][tb[ 0]]; \
            v ^= pitable[1][tb[ 1]]; \
            v ^= pitable[2][tb[ 2]]; \
            v ^= pitable[3][tb[ 3]]; \
            v ^= pitable[4][tb[ 4]]; \
            v ^= pitable[5][tb[ 5]]; \
            v ^= pitable[6][tb[ 6]]; \
            v ^= pitable[7][tb[ 7]]; \
            t[1] ^= v; \
            t[1] ^= ctx->gamma[5]; \
            v  = pitable[0][tb[ 8]]; \
            v ^= pitable[1][tb[ 9]]; \
            v ^= pitable[2][tb[10]]; \
            v ^= pitable[3][tb[11]]; \
            v ^= pitable[4][tb[12]]; \
            v ^= pitable[5][tb[13]]; \
            v ^= pitable[6][tb[14]]; \
            v ^= pitable[7][tb[15]]; \
            t[0] ^= v; \
            ctx->sum[0] ^= t[0]; \
            ctx->sum[1] ^= t[1]; \
         }

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_authenticate_step64( in ) { \
            t[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = *(in)^ctx->gamma[1]; (in)++; \
            authenticationKey->encrypt( &authenticationKey->key, t, t ); \
            authenticationKey->encrypt( &authenticationKey->key, t+1, t+1 ); \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum; \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

 #define ak_xtsmac_encrypt_step64( in, out ) { \
            t[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = *(in)^ctx->gamma[1]; (in)++; \
            encryptionKey->encrypt( &encryptionKey->key, t, t ); \
            encryptionKey->encrypt( &encryptionKey->key, t+1, t+1 ); \
            *(out) = t[0]^ctx->gamma[0]; (out)++; \
            *(out) = t[1]^ctx->gamma[1]; (out)++; \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

 #define ak_xtsmac_decrypt_step64( in, out ) { \
            t[0] = temp[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = temp[1] = *(in)^ctx->gamma[1]; (in)++; \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* расшифровываем данные */ \
            encryptionKey->decrypt( &encryptionKey->key, temp, t ); \
            encryptionKey->decrypt( &encryptionKey->key, temp+1, t+1 ); \
            *(out) = t[0]^ctx->gamma[0]; (out)++; \
            *(out) = t[1]^ctx->gamma[1]; (out)++; \
            ak_xtsmac_next_gamma; \
         }

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_authenticate_step128( in ) { \
            t[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = *(in)^ctx->gamma[1]; (in)++; \
            authenticationKey->encrypt( &authenticationKey->key, t, t ); \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

 #define ak_xtsmac_encrypt_step128( in, out ) { \
            t[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = *(in)^ctx->gamma[1]; (in)++; \
            encryptionKey->encrypt( &encryptionKey->key, t, t ); \
            *(out) = t[0]^ctx->gamma[0]; (out)++; \
            *(out) = t[1]^ctx->gamma[1]; (out)++; \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

 #define ak_xtsmac_decrypt_step128( in, out ) { \
            t[0] = temp[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = temp[1] = *(in)^ctx->gamma[1]; (in)++; \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* расшифровываем данные */ \
            encryptionKey->decrypt( &encryptionKey->key, temp, t ); \
            *(out) = t[0]^ctx->gamma[0]; (out)++; \
            *(out) = t[1]^ctx->gamma[1]; (out)++; \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_update( ak_xtsmac_ctx ctx,
                      ak_bckey authenticationKey, const ak_pointer adata, const size_t adata_size )
{
  register ak_uint64 v = 0;
  const ak_uint64 *inptr = (const ak_uint64 *)adata;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2] = { 0, 0 };
  ak_uint8 *tb = (ak_uint8 *)&t;
  ssize_t tail = ( ssize_t )( adata_size&0xf ),
          blocks = ( ssize_t )( adata_size >> 4 ),
          resource = (( blocks + (tail > 0)) << 1)/( authenticationKey->bsize >> 3 );
                                                                       /* общее количество блоков,
                                                                          подлежащее зашифрованию  */
 /* ни чего не задано => ни чего не обрабатываем */
  if(( adata == NULL ) || ( adata_size == 0 )) return ak_error_ok;

 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_assosiated_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* проверка ресурса ключа */
  if( authenticationKey->key.resource.value.counter < resource )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else authenticationKey->key.resource.value.counter -= resource;

 /* теперь основной цикл */
  switch( authenticationKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          ak_xtsmac_authenticate_step64( inptr );
          ctx->abitlen += 128;
          --blocks;
       }
       if( tail ) {
          ak_uint64 *tptr = temp;
          memcpy( temp, inptr, tail ); /* копируем входные данные (здесь меньше одного 16-ти байтного блока) */
          ak_xtsmac_authenticate_step64( tptr );
          ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
          ctx->abitlen += ( tail << 3 );
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
          ak_xtsmac_authenticate_step128( inptr );
          ctx->abitlen += 128;
          --blocks;
       }
       if( tail ) {
          ak_uint64 *tptr = temp;
          memcpy( temp, inptr, tail ); /* копируем входные данные */
          ak_xtsmac_authenticate_step128( tptr );
          ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
          ctx->abitlen += ( tail << 3 );
       }
       break;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Для завершения процесса вычисления имитовставки мы применяем процедуру шифрования
    для специального блока, который формируется из длин обработаных данных `plen || alen`.
    Результат шифрования подсуммируется к общей контрольной сумме.

    Последним шагом вычисления имитовставки является операция наложения гаммы и зашифрование
    вычисленной контрольной суммы. Полученное в ходе шифрования значение и является результирующим
    значением имитовставки. Формально, реализуемое преобразование может быть описано
    следующим образом

    \f[ \Sigma = \Sigma \oplus \Pi( \texttt{ECB}( K_A, ( \texttt{plen}||\texttt{alen}) \oplus \gamma_{n+1})), \f]

    \f[ Im = \texttt{ECB}( K_A, \Sigma \oplus \gamma_{n+2} ), \f]

    где, как и ранее, `ECB` это режим простой замены,
    \f$ \Pi \f$ - используемое в алгоритме перемешивающее преобразование,
    а `n` это количество 16-ти байтных блоков, преобразованных ранее.
    Во всех операциях шифрования используется ключ аутентификации \f$ K_A \f$.

    \param ctx
    \param authenticationKey
    \param out
    \param out_size
    \return В случае успеха функция возвращает ak_error_ok (ноль).
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_finalize( ak_xtsmac_ctx ctx,
                               ak_bckey authenticationKey, ak_pointer out, const size_t out_size )
{
  register ak_uint64 v;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2];
  ak_uint8 *tb = (ak_uint8 *)&t;

  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to output buffer" );
 /* проверка запрашиваемой длины iv */
  if( out_size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                      "unexpected zero length of integrity code" );
 /* проверка длины блока */
  if( authenticationKey->bsize > 16 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                               "using key with large block size" );
  /* традиционная проверка ресурса */
  if( authenticationKey->key.resource.value.counter <= 0 )
    return ak_error_message( ak_error_low_key_resource, __func__,
                                                                "using key with low key resource");
   else authenticationKey->key.resource.value.counter--;

 /* закрываем добавление шифруемых данных */
   ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );

 /* формируем последний вектор из длин, записанных в big-endian формате */
#ifdef AK_BIG_ENDIAN
    t[0] = ( ak_uint64 )ctx->pbitlen;
    t[1] = ( ak_uint64 )ctx->abitlen;
#else
    t[0] = bswap_64(( ak_uint64 )ctx->pbitlen );
    t[1] = bswap_64(( ak_uint64 )ctx->abitlen );
#endif
    t[0] ^= ctx->gamma[0];
    t[1] ^= ctx->gamma[1];

  if( authenticationKey->bsize == 8 ) {
     authenticationKey->encrypt( &authenticationKey->key, t, t ); \
     authenticationKey->encrypt( &authenticationKey->key, t+1, t+1 ); \
    /* вычисляем слагаемое для имитовставки */ \
     ak_xtsmac_update_sum;
    /* изменяем значение гаммы */
     ak_xtsmac_next_gamma;
    /* последнее шифрование и завершение работы */
     ctx->sum[0] ^= ctx->gamma[0];
     ctx->sum[1] ^= ctx->gamma[1];
     authenticationKey->encrypt( &authenticationKey->key, &ctx->sum, &ctx->sum );
     authenticationKey->encrypt( &authenticationKey->key, &ctx->sum+1, &ctx->sum+1 );

  } else { /* теперь тоже самое, но для 128-битного шифра */
     authenticationKey->encrypt( &authenticationKey->key, t, t ); \
    /* вычисляем слагаемое для имитовставки */ \
     ak_xtsmac_update_sum;
    /* изменяем значение гаммы */
     ak_xtsmac_next_gamma;
    /* последнее шифрование и завершение работы */
     ctx->sum[0] ^= ctx->gamma[0];
     ctx->sum[1] ^= ctx->gamma[1];
     authenticationKey->encrypt( &authenticationKey->key, &ctx->sum, &ctx->sum );
  }

 /* если памяти много (out_size >= 16), то копируем все, что есть, */
            /* в противном случае - только ту часть, что вмещается */
  memcpy( out, ((ak_uint8 *)ctx->sum)+( out_size >= 16 ? 0 : 16 - out_size ),
                                                                           ak_min( out_size, 16 ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_encryption_update( ak_xtsmac_ctx ctx, ak_bckey encryptionKey,
                                          const ak_pointer in, ak_pointer out, const size_t size )
{
  register ak_uint64 v = 0;
  ak_uint64 *outptr = (ak_uint64 *)out;
  const ak_uint64 *inptr = (const ak_uint64 *)in;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2] = { 0, 0 };
  ak_uint8 *tb = (ak_uint8 *)t;
  ssize_t i = 0,
          tail = ( ssize_t )( size&0xf ),
          blocks = ( ssize_t )( size >> 4 ),
          resource = (( blocks + (tail > 0)) << 1)/( encryptionKey->bsize >> 3 );
                                                                       /* общее количество блоков,
                                                                          подлежащее зашифрованию  */
 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;
 /* слишком короткие сообщения не умеем обрабатывать */
  if( !blocks && ( tail > 0 ))
    return ak_error_message( ak_error_wrong_length, __func__ ,
            "xtsmac mode unsupport short messages (length must be equal or more than block size)");
 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* проверка ресурса ключа */
  if( encryptionKey->key.resource.value.counter < resource )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else encryptionKey->key.resource.value.counter -= resource;

 /* теперь основной цикл */
  switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          ak_xtsmac_encrypt_step64( inptr, outptr );
          ctx->pbitlen += 128;
          --blocks;
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
          ak_xtsmac_encrypt_step128( inptr, outptr );
          ctx->pbitlen += 128;
          --blocks;
       }
       break;
  }

  if( tail ) { /* реализуем "скрадывание" шифртекста таким образом, чтобы длина шифртекста
                                                                   совпадала с длиной открытого  */
    size_t adlen = 16 - tail;
    ak_uint64 *tpi = (ak_uint64 *)t, *tpo = (ak_uint64 *)temp;
   /* формируем дополнительный полный блок */
    memcpy( tb, inptr, tail );
    memcpy( tb + tail, ((ak_uint8 *)outptr) - adlen, adlen );
   /* шифруем полученное */
    if( encryptionKey->bsize == 8 ) { ak_xtsmac_encrypt_step64( tpi, tpo ); }
     else { ak_xtsmac_encrypt_step128( tpi, tpo ); }
   /* размещаем по ячейкам */
    for( i = 0; i < tail; i++ ) ((ak_uint8* )outptr)[i] = ((ak_uint8 *)(outptr-2))[i];
       *(outptr-2) = temp[0];
       *(outptr-1) = temp[1];
       ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
       ctx->pbitlen += ( tail << 3 );
    }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_decryption_update( ak_xtsmac_ctx ctx, ak_bckey encryptionKey,
                                          const ak_pointer in, ak_pointer out, const size_t size )
{
  register ak_uint64 v = 0;
  ak_uint64 *outptr = (ak_uint64 *)out;
  const ak_uint64 *inptr = (const ak_uint64 *)in;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2] = { 0, 0 };
  ak_uint8 *tb = (ak_uint8 *)t;
  ssize_t i = 0,
          tail = ( ssize_t )( size&0xf ),
          blocks = ( ssize_t )( size >> 4 ),
          resource = (( blocks + (tail > 0)) << 1)/( encryptionKey->bsize >> 3 );
                                                                       /* общее количество блоков,
                                                                          подлежащее зашифрованию  */
 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;
 /* слишком короткие сообщения не умеем обрабатывать */
  if( !blocks && ( tail > 0 ))
    return ak_error_message( ak_error_wrong_length, __func__ ,
            "xtsmac mode unsupport short messages (length must be equal or more than block size)");

 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* проверка ресурса ключа */
  if( encryptionKey->key.resource.value.counter < resource )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else encryptionKey->key.resource.value.counter -= resource;

 /* теперь основной цикл */
  switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > ( tail > 0 )) {
          ak_xtsmac_decrypt_step64( inptr, outptr );
          ctx->pbitlen += 128;
          --blocks;
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > ( tail > 0 )) {
          ak_xtsmac_decrypt_step128( inptr, outptr );
          ctx->pbitlen += 128;
          --blocks;
       }
       break;
  }

  if( tail ) { /* восстановливаем "скраденый" шифртекст */
    size_t adlen = 16 - tail;
    ak_uint64 *tpi = (ak_uint64 *)t, *tpo = (ak_uint64 *)temp,
              tgam[2] = { ctx->gamma[0], ctx->gamma[1] };

   /* сохраняем текущее значение гаммы и переходим к следующему */
    ak_xtsmac_next_gamma;
   /* расшифровываем последний полный блок */
    if( encryptionKey->bsize == 8 ) { ak_xtsmac_decrypt_step64( inptr, outptr ); }
     else { ak_xtsmac_decrypt_step128( inptr, outptr ); }
    ctx->pbitlen += 128;

   /* формируем дополнительный полный блок */
    memcpy( tb, inptr, tail );
    memcpy( tb + tail, ((ak_uint8 *)outptr) - adlen, adlen );

   /* восстанавливаем значение гаммы и расшифровываем полученное */
    ctx->gamma[0] = tgam[0]; ctx->gamma[1] = tgam[1];
    if( encryptionKey->bsize == 8 ) { ak_xtsmac_decrypt_step64( tpi, tpo ); }
     else { ak_xtsmac_decrypt_step128( tpi, tpo ); }

   /* приводим гамму к ожидаемому виду */
    ak_xtsmac_next_gamma;
   /* размещаем по ячейкам */
    for( i = 0; i < tail; i++ ) ((ak_uint8* )outptr)[i] = ((ak_uint8 *)(outptr-2))[i];
    *(outptr-2) = temp[0];
    *(outptr-1) = temp[1];
    ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
    ctx->pbitlen += ( tail << 3 );

   /* заполняем память мусором */
    ak_ptr_wipe( tgam, sizeof( tgam ), &encryptionKey->key.generator );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует режим `xtsmac` - режим шифрования для блочного шифра с одновременным вычислением
    имитовставки. На вход функции подаются как данные, подлежащие зашифрованию,
    так и ассоциированные данные, которые не зашифровываются. При этом имитовставка вычисляется
    для всех переданных на вход функции данных.

    Режим `xtsmac` должен использовать для шифрования и выработки имитовставки два различных ключа -
    в этом случае длины блоков обрабатываемых данных для ключей должны совпадать (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если хотя бы один из указателей на ключ равен `NULL`, то возбуждается ошибка.

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
           память должна быть выделена заранее; указатель может принимать значение NULL.
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;
           если значение icode_size меньше, чем длина блока, то возвращается запрашиваемое количество
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

 /* проверки ключей */
  if(( encryptionKey == NULL ) || ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,"using null pointer to secret key" );
  if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                    "different block sizes for given secret keys");
 /* подготавливаем память */
  memset( &ctx, 0, sizeof( struct xtsmac_ctx ));

 /* в начале обрабатываем ассоциированные данные */
  if(( error = ak_xtsmac_authentication_clean( &ctx, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),&((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__,
                                           "incorrect initialization of internal xtsmac context" );
  }
  if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),&((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__, "incorrect hashing of associated data" );
  }

 /* потом зашифровываем данные */
  if(( error = ak_xtsmac_encryption_update( &ctx, encryptionKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)encryptionKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect encryption of plain data" );
  }

 /* в конце - вырабатываем имитовставку */
  if(( error = ak_xtsmac_authentication_finalize( &ctx,
                                         authenticationKey, icode, icode_size )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect finanlize of integrity code" );

  ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)authenticationKey)->key.generator );
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
    @param icode_size размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;

    @return Функция возвращает \ref ak_error_ok, если значение имитовтсавки совпало с
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

 /* проверки ключей */
  if(( encryptionKey == NULL ) || ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,"using null pointer to secret key" );
  if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                    "different block sizes for given secret keys");
 /* подготавливаем память */
  memset( &ctx, 0, sizeof( struct xtsmac_ctx ));

 /* в начале обрабатываем ассоциированные данные */
  if(( error = ak_xtsmac_authentication_clean( &ctx, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),&((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__,
                                           "incorrect initialization of internal xtsmac context" );
  }
  if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),&((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__, "incorrect hashing of associated data" );
  }

 /* потом зашифровываем данные */
  if(( error = ak_xtsmac_decryption_update( &ctx, encryptionKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)encryptionKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect encryption of plain data" );
  }

 /* в конце - вырабатываем имитовставку */
  memset( icode2, 0, 16 );
  if(( error = ak_xtsmac_authentication_finalize( &ctx,
                                         authenticationKey, icode2, icode_size )) != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__, "incorrect finanlize of integrity code" );
  }

  ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)authenticationKey)->key.generator );
  if( ak_ptr_is_equal_with_log( icode2, icode, icode_size )) return ak_error_ok;

 return ak_error_not_equal_data;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_xts.c  */
/* ----------------------------------------------------------------------------------------------- */
