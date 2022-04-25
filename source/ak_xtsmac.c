/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2016 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_xtsmac.c                                                                               */
/* ----------------------------------------------------------------------------------------------- */
/* реализация режима аутентифицирующего шифрования xtsmac                                          */
/*                                                                                                 */
/* в редакции статьи A.Yu.Nesterenko,
   Differential properties of authenticated encryption mode based on universal hash function (XTSMAC),
   2021 XVII International Symposium "Problems of Redundancy in Information and Control Systems".
   IEEE, 2021. P. 39-44, doi: https://doi.org/10.1109/REDUNDANCY52534.2021.9606446                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

#ifdef AK_HAVE_STDALIGN_H
 #include <stdalign.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, содержащая текущее состояние внутренних переменных режима
   аутентифицированного шифрования `xtsmac` */
 typedef struct xtsmac_ctx {
  /*! \brief Текущее значение имитовставки
      - 128 бит (16 байт) для Магмы, - 256 бит (32 байта) для Кузнечика */
   ak_uint64 sum[4];
  /*! \brief Вектор, используемый для маскирования шифруемой информации
      \details Для блочного шифра Магма вектор последовательно содержит значения:
        \f$$ \underbrace{\gamma_{2n} || \gamma_{2n+1}}_{128\:\text{бит}} || \underbrace{ k_0 || k_1 || k_2 || k_3 }_{256\:\text{бит}} \f$$, */
   union {
     ak_uint8 u8[80];
     ak_uint64 u64[10];
   } gamma;
  /*! \brief Размер обработанных зашифровываемых/расшифровываемых данных в битах */
   ssize_t pbitlen;
  /*! \brief Размер обработанных ассоциированных данных в битах */
   ssize_t abitlen;
  /*! \brief Флаги состояния контекста */
   ak_uint32 flags;
} *ak_xtsmac_ctx;

/* ----------------------------------------------------------------------------------------------- */
/* выработка следующего значения gamma_{n} в поле F_{2^128}                                        */
/* использует внешний массив ak_uint64 t[2]                                                        */
/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_next_gamma64 { \
      t[0] = ctx->gamma.u64[0] >> 63; \
      t[1] = ctx->gamma.u64[1] >> 63; \
      ctx->gamma.u64[0] <<= 1; ctx->gamma.u64[1] <<= 1; ctx->gamma.u64[1] ^= t[0]; \
      if( t[1] ) ctx->gamma.u64[0] ^= 0x87; \
   }

/* ----------------------------------------------------------------------------------------------- */
/* четырех раундовая сеть Фейстеля на 64х битных блоках                                            */
/* использует внешний массив ak_uint64 t[2]                                                        */
/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_update_sum64 do { \
      register ak_uint64 v = 0; \
      t[0] ^= ctx->gamma.u64[2]; \
      v  = streebog_Areverse_expand_with_pi[0][tb[ 0]]; \
      v ^= streebog_Areverse_expand_with_pi[1][tb[ 1]]; \
      v ^= streebog_Areverse_expand_with_pi[2][tb[ 2]]; \
      v ^= streebog_Areverse_expand_with_pi[3][tb[ 3]]; \
      v ^= streebog_Areverse_expand_with_pi[4][tb[ 4]]; \
      v ^= streebog_Areverse_expand_with_pi[5][tb[ 5]]; \
      v ^= streebog_Areverse_expand_with_pi[6][tb[ 6]]; \
      v ^= streebog_Areverse_expand_with_pi[7][tb[ 7]]; \
      t[1] ^= v; \
      t[1] ^= ctx->gamma.u64[3]; \
      v  = streebog_Areverse_expand_with_pi[0][tb[ 8]]; \
      v ^= streebog_Areverse_expand_with_pi[1][tb[ 9]]; \
      v ^= streebog_Areverse_expand_with_pi[2][tb[10]]; \
      v ^= streebog_Areverse_expand_with_pi[3][tb[11]]; \
      v ^= streebog_Areverse_expand_with_pi[4][tb[12]]; \
      v ^= streebog_Areverse_expand_with_pi[5][tb[13]]; \
      v ^= streebog_Areverse_expand_with_pi[6][tb[14]]; \
      v ^= streebog_Areverse_expand_with_pi[7][tb[15]]; \
      t[0] ^= v; \
      t[0] ^= ctx->gamma.u64[4]; \
      v  = streebog_Areverse_expand_with_pi[0][tb[ 0]]; \
      v ^= streebog_Areverse_expand_with_pi[1][tb[ 1]]; \
      v ^= streebog_Areverse_expand_with_pi[2][tb[ 2]]; \
      v ^= streebog_Areverse_expand_with_pi[3][tb[ 3]]; \
      v ^= streebog_Areverse_expand_with_pi[4][tb[ 4]]; \
      v ^= streebog_Areverse_expand_with_pi[5][tb[ 5]]; \
      v ^= streebog_Areverse_expand_with_pi[6][tb[ 6]]; \
      v ^= streebog_Areverse_expand_with_pi[7][tb[ 7]]; \
      t[1] ^= v; \
      t[1] ^= ctx->gamma.u64[5]; \
      v  = streebog_Areverse_expand_with_pi[0][tb[ 8]]; \
      v ^= streebog_Areverse_expand_with_pi[1][tb[ 9]]; \
      v ^= streebog_Areverse_expand_with_pi[2][tb[10]]; \
      v ^= streebog_Areverse_expand_with_pi[3][tb[11]]; \
      v ^= streebog_Areverse_expand_with_pi[4][tb[12]]; \
      v ^= streebog_Areverse_expand_with_pi[5][tb[13]]; \
      v ^= streebog_Areverse_expand_with_pi[6][tb[14]]; \
      v ^= streebog_Areverse_expand_with_pi[7][tb[15]]; \
      t[0] ^= v; \
      ctx->sum[0] ^= t[0]; \
      ctx->sum[1] ^= t[1]; \
   } while(0);

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_authenticate_step64( inptr ) { \
     t[0] = *(inptr)^ctx->gamma.u64[0]; (inptr)++; \
     t[1] = *(inptr)^ctx->gamma.u64[1]; (inptr)++; \
     authenticationKey->encrypt( &authenticationKey->key, t, t ); \
     authenticationKey->encrypt( &authenticationKey->key, t +1, t +1 ); \
    /* обновляем промежуточное состояние имитовставки */ \
     ak_xtsmac_update_sum64; \
    /* изменяем значение маскирующей гаммы */ \
     ak_xtsmac_next_gamma64; \
   }

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_encrypt_step64( inptr, outptr ) do { \
     t[0] = *(inptr)^ctx->gamma.u64[0]; (inptr)++; \
     t[1] = *(inptr)^ctx->gamma.u64[1]; (inptr)++; \
     encryptionKey->encrypt( &encryptionKey->key, t, t ); \
     encryptionKey->encrypt( &encryptionKey->key, t +1, t +1 ); \
     *(outptr) = t[0]^ctx->gamma.u64[0]; (outptr)++; \
     *(outptr) = t[1]^ctx->gamma.u64[1]; (outptr)++; \
    /* обновляем промежуточное состояние имитовставки */ \
     ak_xtsmac_update_sum64; \
    /* изменяем значение маскирующей гаммы */ \
     ak_xtsmac_next_gamma64; \
   } while(0);

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_decrypt_step64( inptr, outptr ) do { \
     t[0] = temp[0] = *(inptr)^ctx->gamma.u64[0]; (inptr)++; \
     t[1] = temp[1] = *(inptr)^ctx->gamma.u64[1]; (inptr)++; \
    /* обновляем промежуточное состояние имитовставки */ \
     ak_xtsmac_update_sum64; \
    /* расшифровываем данные */ \
     encryptionKey->decrypt( &encryptionKey->key, temp, t ); \
     encryptionKey->decrypt( &encryptionKey->key, temp +1, t +1 ); \
     *(outptr) = t[0]^ctx->gamma.u64[0]; (outptr)++; \
     *(outptr) = t[1]^ctx->gamma.u64[1]; (outptr)++; \
    /* изменяем значение маскирующей гаммы */ \
     ak_xtsmac_next_gamma64; \
   } while(0);

/* ----------------------------------------------------------------------------------------------- */
/*                             реализация пошаговой стратегии вычислений                           */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста перед вычислением имитовставки и шифрованием информации

    \details Функция вычисляет начальное значение внутреннего состояния `gamma`
    из заданного значения синхропосылки с помощью равенства `gamma = CBC( K, iv, 0 )`,
    т.е. зашифровывает синхропосылку `iv`, переданную в аргументах функции,
    в режиме `cbc` с использованием нулевого вектора в качестве синхропосылки.

    \param actx контекст алгоритма xtsmac
    \param akey ключ аутентификации (должен быть ключом блочного алгоритма шифрования)
    \param iv указатель на область памяти, где хранится синхропосылка.
    \param iv_size размер синхропосылки (в октетах), ожидаемое значение -- два блока,
    но может принимать любое, отличное от нуля значение.

    \note Ожидаемый размер синхропосылки должен составлять два блока блочного шифра.
    Если аргумент `iv_size` содержит меньшую длину, то синхропосылка дополняется нулями
    в старших разрядах. Если `iv_size` большую длину, то лишние октеты отбрасываются.

    \return В случае успеха функция возвращает ноль (ak_error_ok). В случае
    возникновения ошибки возвращается ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_clean( ak_pointer actx,
                                       ak_pointer akey, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  ak_xtsmac_ctx ctx = actx;
  ak_bckey authenticationKey = akey;
  ak_uint8 ivcbc[16] = { 0x35, 0xea, 0x16, 0xc4, 0x06, 0x36, 0x3a, 0x30,
                                                  0xbf, 0x0b, 0x2e, 0x69, 0x39, 0x92, 0xb5, 0x8f };
 /* в качестве константы используется не последовательность нулей, как в исходной статье,
    а последовательность коэффициентов разложения числа pi, начиная с 100000 знака */

  if( authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                       "using null pointer to authentication key");
  if( authenticationKey->key.oid->engine != block_cipher )
    return ak_error_message( ak_error_oid_engine, __func__,
                                                     "using non block cipher authentication key" );
  /* проверка длины блока */
  if( authenticationKey->bsize > 16 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                               "using key with large block size" );
  if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to initial vector");
  if( !iv_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                           "using initial vector of zero length" );
 /* обнуляем необходимое */
  memset( ctx, 0, sizeof( struct xtsmac_ctx ));

 /* на старте имеем вектор длины 6 блоков, из которых
    - первые два блока содержат значение iv,
    - остальные четыре блока заполнены нулями.

    далее, формируется gamma и производные ключи k_0, k_1, k_2 и k_3,
    путем зашифрования в режиме cbc исходного вектора с фиксированным значением синхропосылки ivcbc

    в исходной статье вместо производного ключа используется исходный ключ имитозащиты */
  memcpy( ctx->gamma.u8, iv, ak_min( iv_size, 2*authenticationKey->bsize ));
  if(( error = ak_bckey_encrypt_cbc( authenticationKey, ctx->gamma.u8, ctx->gamma.u8,
                 6*authenticationKey->bsize, ivcbc, sizeof( ivcbc ))) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect initialization of gamma values" );

 /* посмотреть значение производного ключа можно так
  printf("гамма: %s\n", ak_ptr_to_hexstr( ctx->gamma.u8, 2*authenticationKey->bsize, ak_false ));
  printf("ключ:  %s\n", ak_ptr_to_hexstr( ctx->gamma.u8 +2*authenticationKey->bsize,
                                                          4*authenticationKey->bsize, ak_false )); */
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
  ak_xtsmac_ctx ctx = actx;
  ak_bckey authenticationKey = akey;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2];
  ak_uint8 *tb = (ak_uint8 *)&t;
  ssize_t absize = (( ssize_t ) authenticationKey->bsize ) << 1;
  ssize_t tail = ( ssize_t ) adata_size%absize,
          blocks = ( ssize_t ) adata_size/absize;
  const ak_uint64 *inptr = ( const ak_uint64 * )adata;

 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_assosiated_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* ни чего не задано => ни чего не обрабатываем */
  if(( adata == NULL ) || ( adata_size == 0 )) return ak_error_ok;

 /* теперь основной цикл */
  if( absize == 32 ) { /* обработка 128-битным шифром */

    return ak_error_message_fmt( ak_error_undefined_function, __func__,
                      "unsupported block cipher: %s, sorry", authenticationKey->key.oid->name[0] );

  }
   else { /* обработка 64-битным шифром */
      while( blocks-- > 0 ) {
        ak_xtsmac_authenticate_step64( inptr );
        ctx->abitlen += 128;
      }
      if( tail ) {
        ak_uint64 *tptr = temp;
        memset( temp, 0, sizeof( temp ));
        memcpy( temp, inptr, tail ); /* копируем входные данные (здесь меньше одного 16-ти байтного блока) */
        ak_xtsmac_authenticate_step64( tptr );
       /* запрещаем добавление данных */
        ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
        ctx->abitlen += ( tail << 3 );
      }
    }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_finalize( ak_pointer actx,
                                           ak_pointer akey, ak_pointer out, const size_t out_size )
{
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2], *tptr = temp;
  ak_uint8 *tb = (ak_uint8 *)&t;
  ak_bckey authenticationKey = akey;
  ak_xtsmac_ctx ctx = actx;
  size_t b2 = ( authenticationKey->bsize << 1 );

  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to output buffer" );
 /* проверка запрашиваемой длины iv */
  if( out_size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                      "unexpected zero length of integrity code" );
 /* закрываем какое-либо добавление данных */
  if(( ctx->flags&ak_aead_assosiated_data_bit ) == 0 )
    ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
  ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );

 /* формируем последний вектор из длин, записанных в big-endian формате */
#ifdef AK_BIG_ENDIAN
  temp[0] = ( ak_uint64 )ctx->pbitlen;
  temp[1] = ( ak_uint64 )ctx->abitlen;
#else
  temp[0] = bswap_64(( ak_uint64 )ctx->pbitlen );
  temp[1] = bswap_64(( ak_uint64 )ctx->abitlen );
#endif
  ak_xtsmac_authenticate_step64( tptr );

  if( authenticationKey->bsize == 16 ) {
    return ak_error_message_fmt( ak_error_undefined_function, __func__,
                      "unsupported block cipher: %s, sorry", authenticationKey->key.oid->name[0] );
  }
   else {
    /* в отличие от статьи, дополнительно складываем со значением gamma[0],
       вычисленным в момент обработки длин,
       т.е. мы применяем режим cbc со значением синхропослылки, равным gamma[0] */
     ctx->sum[0] ^= ctx->gamma.u64[0];
     authenticationKey->encrypt( &authenticationKey->key, ctx->sum, ctx->sum );
     ctx->sum[1] ^= ctx->sum[0];
     authenticationKey->encrypt( &authenticationKey->key, ctx->sum +1, ctx->sum +1 );
   }

 /* если памяти много (out_size >= 16), то копируем все, что есть, */
            /* в противном случае - только ту часть, что вмещается */
  memcpy( out, ((ak_uint8 *)ctx->sum)+( out_size >= b2 ? 0 : b2 - out_size ),
                                                                           ak_min( out_size, b2 ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_encryption_update( ak_pointer actx, ak_pointer ekey, ak_pointer akey,
                                          const ak_pointer in, ak_pointer out, const size_t size )
{
  ak_xtsmac_ctx ctx = actx;
  ak_bckey encryptionKey = ekey;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2];
  ak_uint8 *tb = (ak_uint8 *)&t;
  ssize_t absize = (( ssize_t ) encryptionKey->bsize ) << 1;
  ssize_t tail = ( ssize_t ) size%absize,
          blocks = ( ssize_t ) size/absize;
  const ak_uint64 *inptr = in;
  ak_uint64 *outptr = out;

 /* проверка указателя */
  if( ekey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to encryption key" );
 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* слишком короткие сообщения не умеем обрабатывать */
  if( !blocks && ( tail < encryptionKey->bsize ))
    return ak_error_message( ak_error_wrong_length, __func__ ,
                                "xtsmac mode cannot encrypt short messages "
                                                 "(length must be equal or more than block size)");

 /* далее мы реализуем три пути развития событий:
    - случай, когда данные выровнены по длине пары блоков, т.е. tail = 0
    - случай, когда количество пар блоков больше нуля, вне зависимости от значения tail > 0
    - случай, когда пар блоков нет, но tail не менее длины одного блока (и не более двух) */

 /* 1. случай данных, выровненных по длине пары блоков */
  if( !tail ) {
    switch( encryptionKey->bsize ) {
       case  8:
         while( blocks-- > 0 ) {
            ak_xtsmac_encrypt_step64( inptr, outptr );
            ctx->pbitlen += 128;
         }
         break;

       case  16:
         return ak_error_message_fmt( ak_error_undefined_function, __func__,
                      "unsupported block cipher: %s, sorry", encryptionKey->key.oid->name[0] );
       break;
    }
    return ak_error_ok;
  }

 /* 2. случай, когда пар блоков нет и tail не менее одного блока данных,
    здесь реализуется скрадывание на первом полном блоке */
  if( !blocks && ( tail >= encryptionKey->bsize )) {
    if( encryptionKey->bsize == 16 ) {

      return ak_error_message_fmt( ak_error_undefined_function, __func__,
                      "unsupported block cipher: %s, sorry", encryptionKey->key.oid->name[0] );
    }
     else { /* реализация для 64-х битного шифра */
      /* копируем входные данные */
        memset( t, 0, sizeof( t ));
        memcpy( t, inptr, tail );
      /* шифруем левый блок */
        t[0] ^= ctx->gamma.u64[0];
        encryptionKey->encrypt( &encryptionKey->key, t, t );
        t[0] ^= ctx->gamma.u64[0];
       /* добавляем правый блок до полной длины, где
          число недостающих октов равно 16 -tail,
          длина данных, превышающая длину блока tail -8 */
        memcpy( tb + tail, tb + tail - 8, 16 - tail );
       /* шифруем правый блок */
        t[1] ^= ctx->gamma.u64[1];
        encryptionKey->encrypt( &encryptionKey->key, t +1, t +1 );
        t[1] ^= ctx->gamma.u64[1];
       /* копируем результат вычислений */
        memcpy( (ak_uint8 *)out, tb +8, 8 );
        memcpy( (ak_uint8 *)out +8, tb, tail - 8 );
       /* обновляем промежуточное состояние имитовставки */
        ak_xtsmac_update_sum64;
       /* изменяем значение маскирующей гаммы */
        ak_xtsmac_next_gamma64;
     }
    /* закрываем возможность дальнейшего шифрования */
     ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
     return ak_error_ok;
  }

 /* 3. случай, когда пары блоков несколько (не менее одной), а tail принимает любое возможное значение
    здесь реализуется скрадывание на парах блоков */

 return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_decryption_update( ak_pointer actx, ak_pointer ekey, ak_pointer akey,
                                          const ak_pointer in, ak_pointer out, const size_t size )
{
  ak_xtsmac_ctx ctx = actx;
  ak_bckey encryptionKey = ekey;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2];
  ak_uint8 *tb = (ak_uint8 *)&t;
  ssize_t absize = (( ssize_t ) encryptionKey->bsize ) << 1;
  ssize_t tail = ( ssize_t ) size%absize,
          blocks = ( ssize_t ) size/absize;
  const ak_uint64 *inptr = in;
  ak_uint64 *outptr = out;

 /* проверка указателя */
  if( ekey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to encryption key" );
 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* слишком короткие сообщения не умеем обрабатывать */
  if( !blocks && ( tail < encryptionKey->bsize ))
    return ak_error_message( ak_error_wrong_length, __func__ ,
                                "xtsmac mode cannot encrypt short messages "
                                                 "(length must be equal or more than block size)");

 /* далее, также как и при зашифровании, мы реализуем три пути развития событий:
    - случай, когда данные выровнены по длине пары блоков, т.е. tail = 0
    - случай, когда количество пар блоков больше нуля, вне зависимости от значения tail > 0
    - случай, когда пар блоков нет, но tail не менее длины одного блока (и не более двух) */

 /* 1. случай данных, выровненных по длине пары блоков */
  if( !tail ) {
    switch( encryptionKey->bsize ) {
       case  8:
         while( blocks-- > 0 ) {
            ak_xtsmac_decrypt_step64( inptr, outptr );
            ctx->pbitlen += 128;
         }
         break;

       case  16:
         return ak_error_message_fmt( ak_error_undefined_function, __func__,
                      "unsupported block cipher: %s, sorry", encryptionKey->key.oid->name[0] );
       break;
    }
    return ak_error_ok;
  }

 /* 2. случай, когда пар блоков нет и tail не менее одного блока данных,
    здесь реализуется скрадывание на первом полном блоке */
  if( !blocks && ( tail >= encryptionKey->bsize )) {
    if( encryptionKey->bsize == 16 ) {

      return ak_error_message_fmt( ak_error_undefined_function, __func__,
                      "unsupported block cipher: %s, sorry", encryptionKey->key.oid->name[0] );
    }
     else { /* реализация для 64-х битного шифра */
        ak_uint64 buf[1];

       /* копируем входные данные */
        memset( tb, 0, sizeof( t ));
        memcpy( tb, (ak_uint8 *)in +8, tail -8 );
        memcpy( tb +8, (ak_uint8 *)in, 8 );
       /* расшифровываем левый блок во временную переменную */
        buf[0] = t[1]^ctx->gamma.u64[1];
        encryptionKey->decrypt( &encryptionKey->key, buf, buf );
        buf[0] ^= ctx->gamma.u64[1];
       /* копируем хвост расшифрованных даных для повторного расшифрования */
        memcpy( tb + tail - 8, (ak_uint8 *)buf + tail - 8, 16 - tail );
       /* расшифровываем правый блок и формируем открытый текст */
        outptr[0] = t[0]^ctx->gamma.u64[0];
        encryptionKey->decrypt( &encryptionKey->key, outptr, outptr );
        outptr[0] ^= ctx->gamma.u64[0];
       /* обновляем промежуточное состояние имитовставки */
        ak_xtsmac_update_sum64;
       /* изменяем значение маскирующей гаммы */
        ak_xtsmac_next_gamma64;
        memcpy( (ak_uint8 *)out +8, (ak_uint8 *)buf, tail -8 );
     }
    /* закрываем возможность дальнейшего расшифрования */
     ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
     return ak_error_ok;
  }

 return ak_error_undefined_function;
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

 /* первичная инициализация */
  if(( error = ak_xtsmac_authentication_clean( &ctx, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
    if( authenticationKey != NULL ) ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),
                                                   &((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__,
                                           "incorrect initialization of internal xtsmac context" );
  }

 /* проверка совпадения длин блоков для секретных ключе */
  if( encryptionKey != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                    "different block sizes for given secret keys");
  }

 /* обрабатываем ассоциированные данные */
  if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey, adata, adata_size ))
                                                                                != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect hashing of associated data" );
    goto exlab;
  }

 /* потом зашифровываем данные */
  if( encryptionKey != NULL ) {
    if(( error = ak_xtsmac_encryption_update( &ctx, encryptionKey, authenticationKey,
                                                               in, out, size )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect encryption of plain data" );
      goto exlab;
    }
  }

 /* завершаем функцию вычислением имитовставки */
  if(( error = ak_xtsmac_authentication_finalize( &ctx,
                                          authenticationKey, icode, icode_size )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect finalization of integrity code" );

 exlab:
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
  ak_uint8 ic[32];
  int error = ak_error_ok;
  struct xtsmac_ctx ctx; /* контекст структуры, в которой хранятся промежуточные данные */

 /* первичная инициализация */
  if(( error = ak_xtsmac_authentication_clean( &ctx, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
    if( authenticationKey != NULL ) ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),
                                                   &((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__,
                                           "incorrect initialization of internal xtsmac context" );
  }

 /* проверка совпадения длин блоков для секретных ключе */
  if( encryptionKey != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                    "different block sizes for given secret keys");
  }

 /* обрабатываем ассоциированные данные */
  if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey, adata, adata_size ))
                                                                                != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect hashing of associated data" );
    goto exlab;
  }

 /* потом зашифровываем данные */
  if( encryptionKey != NULL ) {
    if(( error = ak_xtsmac_decryption_update( &ctx, encryptionKey, authenticationKey,
                                                               in, out, size )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect decryption of plain data" );
      goto exlab;
    }
  }

 /* завершаем функцию вычислением имитовставки */
  memset( ic, 0, sizeof( ic ));
  if(( error = ak_xtsmac_authentication_finalize( &ctx,
                                           authenticationKey, ic, icode_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect finalization of integrity code" );
    goto exlab;
  }

  if( ak_ptr_is_equal_with_log( ic, icode, ak_min( icode_size, sizeof( ic ))) != ak_true )
    error = ak_error_not_equal_data;

 exlab:
  ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)authenticationKey)->key.generator );
 return error;
}

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

   ctx->tag_size = ctx->iv_size = ctx->block_size = 16; /* длина блока алгоритма Магма */
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
  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_xtsmac.c  */
/* ----------------------------------------------------------------------------------------------- */
