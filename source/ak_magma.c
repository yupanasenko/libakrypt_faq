/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                            by Mikhail Lavrinovich, mikhail.lavrinovich@netcracker.com           */
/*                                                                                                 */
/*  Файл ak_magma.h                                                                                */
/*  - содержит реализацию алгоритма блочного шифрования Магма,                                     */
/*    регламентированного ГОСТ Р 34.12-2015                                                        */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>
 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief  Структура для хранения внутренних данных в маскированной реализации Магмы. */
 struct magma_encrypted_keys {
  /*! \brief  Две ключевые последовательности - прямая и инвертированная. */
  ak_uint32 inkey[2][8];
  /*! \brief  Две маски для двух ключевых последовательностей, соответственно,
      прямой и инвертированной. */
  ak_uint32 inmask[2][8];
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует один такт шифрующего преобразования ГОСТ 34.12-2015 (Mагма).

    @param x Обрабатываемая половина блока (более детально смотри описание сети Фейстеля).
    @return Результат криптографического преобразования.                                           */
/* ----------------------------------------------------------------------------------------------- */
 static inline ak_uint32 ak_magma_gostf_boxes( ak_uint32 x, const ak_uint8 i, const ak_uint8 j )
{
  x = magma_boxes[j][i][3][x>>24 & 255] << 24 | magma_boxes[j][i][2][x>>16 & 255] << 16 |
                           magma_boxes[j][i][1][x>> 8 & 255] <<  8 | magma_boxes[j][i][0][x & 255];
  return x<<11 | x>>(32-11);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция зашифрования одного блока информации алгоритмом ГОСТ 34.12-2015 (Магма).

    @param skey Контекст секретного ключа.
    @param in Блок входной информации (открытый текст).
    @param out Блок выходной информации (шифртекст).                                               */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_magma_encrypt_with_random_walk( ak_skey skey, ak_pointer in, ak_pointer out )
{
  ak_uint8 m[34];
  ak_uint32 i, mv = 0;
  ak_uint32 (*kp)[8] = ((struct magma_encrypted_keys *)skey->data)->inkey;
  ak_uint32 (*mp)[8] = ((struct magma_encrypted_keys *)skey->data)->inmask;
  register ak_uint32 n3, n4, p = 0;

 /* вырабатываем случайную траекторию */
  skey->generator.random( &skey->generator, &mv, sizeof( ak_uint32 ));

 /* формируем вектор раундовых поворотов */
  m[0] = m[33] = 0;
  for( i = 0; i < 32; i++ ) m[i+1] = (ak_uint8)(( mv >> i) & 0x01 );

 /* начинаем движение */
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  n3 = ((ak_uint32 *) in)[0]^( m[1] * 0xffffffff );
  n4 = ((ak_uint32 *) in)[1];
#else
  n3 = bswap_32( ((ak_uint32 *) in)[0] )^( m[1] * 0xffffffff );
  n4 = bswap_32( ((ak_uint32 *) in)[1] );
#endif

  p = n3; p -= mp[m[ 1]][7]; p += kp[m[ 1]][7] + m[ 1]; n4 ^= ak_magma_gostf_boxes( p, m[ 2] ^ m[ 0], m[ 1] );
  p = n4; p -= mp[m[ 2]][6]; p += kp[m[ 2]][6] + m[ 2]; n3 ^= ak_magma_gostf_boxes( p, m[ 3] ^ m[ 1], m[ 2] );
  p = n3; p -= mp[m[ 3]][5]; p += kp[m[ 3]][5] + m[ 3]; n4 ^= ak_magma_gostf_boxes( p, m[ 4] ^ m[ 2], m[ 3] );
  p = n4; p -= mp[m[ 4]][4]; p += kp[m[ 4]][4] + m[ 4]; n3 ^= ak_magma_gostf_boxes( p, m[ 5] ^ m[ 3], m[ 4] );
  p = n3; p -= mp[m[ 5]][3]; p += kp[m[ 5]][3] + m[ 5]; n4 ^= ak_magma_gostf_boxes( p, m[ 6] ^ m[ 4], m[ 5] );
  p = n4; p -= mp[m[ 6]][2]; p += kp[m[ 6]][2] + m[ 6]; n3 ^= ak_magma_gostf_boxes( p, m[ 7] ^ m[ 5], m[ 6] );
  p = n3; p -= mp[m[ 7]][1]; p += kp[m[ 7]][1] + m[ 7]; n4 ^= ak_magma_gostf_boxes( p, m[ 8] ^ m[ 6], m[ 7] );
  p = n4; p -= mp[m[ 8]][0]; p += kp[m[ 8]][0] + m[ 8]; n3 ^= ak_magma_gostf_boxes( p, m[ 9] ^ m[ 7], m[ 8] );

  p = n3; p -= mp[m[ 9]][7]; p += kp[m[ 9]][7] + m[ 9]; n4 ^= ak_magma_gostf_boxes( p, m[10] ^ m[ 8], m[ 9] );
  p = n4; p -= mp[m[10]][6]; p += kp[m[10]][6] + m[10]; n3 ^= ak_magma_gostf_boxes( p, m[11] ^ m[ 9], m[10] );
  p = n3; p -= mp[m[11]][5]; p += kp[m[11]][5] + m[11]; n4 ^= ak_magma_gostf_boxes( p, m[12] ^ m[10], m[11] );
  p = n4; p -= mp[m[12]][4]; p += kp[m[12]][4] + m[12]; n3 ^= ak_magma_gostf_boxes( p, m[13] ^ m[11], m[12] );
  p = n3; p -= mp[m[13]][3]; p += kp[m[13]][3] + m[13]; n4 ^= ak_magma_gostf_boxes( p, m[14] ^ m[12], m[13] );
  p = n4; p -= mp[m[14]][2]; p += kp[m[14]][2] + m[14]; n3 ^= ak_magma_gostf_boxes( p, m[15] ^ m[13], m[14] );
  p = n3; p -= mp[m[15]][1]; p += kp[m[15]][1] + m[15]; n4 ^= ak_magma_gostf_boxes( p, m[16] ^ m[14], m[15] );
  p = n4; p -= mp[m[16]][0]; p += kp[m[16]][0] + m[16]; n3 ^= ak_magma_gostf_boxes( p, m[17] ^ m[15], m[16] );

  p = n3; p -= mp[m[17]][7]; p += kp[m[17]][7] + m[17]; n4 ^= ak_magma_gostf_boxes( p, m[18] ^ m[16], m[17] );
  p = n4; p -= mp[m[18]][6]; p += kp[m[18]][6] + m[18]; n3 ^= ak_magma_gostf_boxes( p, m[19] ^ m[17], m[18] );
  p = n3; p -= mp[m[19]][5]; p += kp[m[19]][5] + m[19]; n4 ^= ak_magma_gostf_boxes( p, m[20] ^ m[18], m[19] );
  p = n4; p -= mp[m[20]][4]; p += kp[m[20]][4] + m[20]; n3 ^= ak_magma_gostf_boxes( p, m[21] ^ m[19], m[20] );
  p = n3; p -= mp[m[21]][3]; p += kp[m[21]][3] + m[21]; n4 ^= ak_magma_gostf_boxes( p, m[22] ^ m[20], m[21] );
  p = n4; p -= mp[m[22]][2]; p += kp[m[22]][2] + m[22]; n3 ^= ak_magma_gostf_boxes( p, m[23] ^ m[21], m[22] );
  p = n3; p -= mp[m[23]][1]; p += kp[m[23]][1] + m[23]; n4 ^= ak_magma_gostf_boxes( p, m[24] ^ m[22], m[23] );
  p = n4; p -= mp[m[24]][0]; p += kp[m[24]][0] + m[24]; n3 ^= ak_magma_gostf_boxes( p, m[25] ^ m[23], m[24] );

  p = n3; p -= mp[m[25]][0]; p += kp[m[25]][0] + m[25]; n4 ^= ak_magma_gostf_boxes( p, m[26] ^ m[24], m[25] );
  p = n4; p -= mp[m[26]][1]; p += kp[m[26]][1] + m[26]; n3 ^= ak_magma_gostf_boxes( p, m[27] ^ m[25], m[26] );
  p = n3; p -= mp[m[27]][2]; p += kp[m[27]][2] + m[27]; n4 ^= ak_magma_gostf_boxes( p, m[28] ^ m[26], m[27] );
  p = n4; p -= mp[m[28]][3]; p += kp[m[28]][3] + m[28]; n3 ^= ak_magma_gostf_boxes( p, m[29] ^ m[27], m[28] );
  p = n3; p -= mp[m[29]][4]; p += kp[m[29]][4] + m[29]; n4 ^= ak_magma_gostf_boxes( p, m[30] ^ m[28], m[29] );
  p = n4; p -= mp[m[30]][5]; p += kp[m[30]][5] + m[30]; n3 ^= ak_magma_gostf_boxes( p, m[31] ^ m[29], m[30] );
  p = n3; p -= mp[m[31]][6]; p += kp[m[31]][6] + m[31]; n4 ^= ak_magma_gostf_boxes( p, m[32] ^ m[30], m[31] );
  p = n4; p -= mp[m[32]][7]; p += kp[m[32]][7] + m[32]; n3 ^= ak_magma_gostf_boxes( p, m[33] ^ m[31], m[32] );

 #ifdef LIBAKRYPT_LITTLE_ENDIAN
  ((ak_uint32 *)out)[0] = n4^( m[32] * 0xffffffff ); ((ak_uint32 *)out)[1] = n3;
 #else
  ((ak_uint32 *)out)[0] = bswap_32( n4 )^( m[32] * 0xffffffff ); ((ak_uint32 *)out)[1] = bswap_32( n3 );
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция расшифрования одного блока информации маскированного
    алгоритмом ГОСТ 34.12-2015 (Магма).

    @param skey Контекст секретного ключа.
    @param in Блок входной информации (шифртекст).
    @param out Блок выходной информации (открытый текст).                                          */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_magma_decrypt_with_random_walk( ak_skey skey, ak_pointer in, ak_pointer out )
{
  ak_uint8 m[34];
  ak_uint32 i, mv = 0;
  ak_uint32 (*kp)[8] = ((struct magma_encrypted_keys *)skey->data)->inkey;
  ak_uint32 (*mp)[8] = ((struct magma_encrypted_keys *)skey->data)->inmask;
  register ak_uint32 n3, n4, p = 0;

 /* вырабатываем случайную траекторию */
  skey->generator.random( &skey->generator, &mv, sizeof( ak_uint32 ));

 /* формируем вектор раундовых поворотов */
  m[0] = m[33] = 0;
  for( i = 0; i < 32; i++ ) m[i+1] = (ak_uint8)((mv >> i) & 0x01 );

 /* начинаем движение */
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  n3 = ((ak_uint32 *) in)[0]^( m[1] * 0xffffffff );
  n4 = ((ak_uint32 *) in)[1];
#else
  n3 = bswap_32( ((ak_uint32 *) in)[0] )^( m[1] * 0xffffffff );
  n4 = bswap_32( ((ak_uint32 *) in)[1] );
#endif

  p = (n3 - mp[m[ 1]][7]); p += kp[m[ 1]][7] + m[ 1]; n4 ^= ak_magma_gostf_boxes(p, m[ 2] ^ m[ 0], m[ 1] );
  p = (n4 - mp[m[ 2]][6]); p += kp[m[ 2]][6] + m[ 2]; n3 ^= ak_magma_gostf_boxes(p, m[ 3] ^ m[ 1], m[ 2] );
  p = (n3 - mp[m[ 3]][5]); p += kp[m[ 3]][5] + m[ 3]; n4 ^= ak_magma_gostf_boxes(p, m[ 4] ^ m[ 2], m[ 3] );
  p = (n4 - mp[m[ 4]][4]); p += kp[m[ 4]][4] + m[ 4]; n3 ^= ak_magma_gostf_boxes(p, m[ 5] ^ m[ 3], m[ 4] );
  p = (n3 - mp[m[ 5]][3]); p += kp[m[ 5]][3] + m[ 5]; n4 ^= ak_magma_gostf_boxes(p, m[ 6] ^ m[ 4], m[ 5] );
  p = (n4 - mp[m[ 6]][2]); p += kp[m[ 6]][2] + m[ 6]; n3 ^= ak_magma_gostf_boxes(p, m[ 7] ^ m[ 5], m[ 6] );
  p = (n3 - mp[m[ 7]][1]); p += kp[m[ 7]][1] + m[ 7]; n4 ^= ak_magma_gostf_boxes(p, m[ 8] ^ m[ 6], m[ 7] );
  p = (n4 - mp[m[ 8]][0]); p += kp[m[ 8]][0] + m[ 8]; n3 ^= ak_magma_gostf_boxes(p, m[ 9] ^ m[ 7], m[ 8] );

  p = (n3 - mp[m[ 9]][0]); p += kp[m[ 9]][0] + m[ 9]; n4 ^= ak_magma_gostf_boxes(p, m[10] ^ m[ 8], m[ 9] );
  p = (n4 - mp[m[10]][1]); p += kp[m[10]][1] + m[10]; n3 ^= ak_magma_gostf_boxes(p, m[11] ^ m[ 9], m[10] );
  p = (n3 - mp[m[11]][2]); p += kp[m[11]][2] + m[11]; n4 ^= ak_magma_gostf_boxes(p, m[12] ^ m[10], m[11] );
  p = (n4 - mp[m[12]][3]); p += kp[m[12]][3] + m[12]; n3 ^= ak_magma_gostf_boxes(p, m[13] ^ m[11], m[12] );
  p = (n3 - mp[m[13]][4]); p += kp[m[13]][4] + m[13]; n4 ^= ak_magma_gostf_boxes(p, m[14] ^ m[12], m[13] );
  p = (n4 - mp[m[14]][5]); p += kp[m[14]][5] + m[14]; n3 ^= ak_magma_gostf_boxes(p, m[15] ^ m[13], m[14] );
  p = (n3 - mp[m[15]][6]); p += kp[m[15]][6] + m[15]; n4 ^= ak_magma_gostf_boxes(p, m[16] ^ m[14], m[15] );
  p = (n4 - mp[m[16]][7]); p += kp[m[16]][7] + m[16]; n3 ^= ak_magma_gostf_boxes(p, m[17] ^ m[15], m[16] );

  p = (n3 - mp[m[17]][0]); p += kp[m[17]][0] + m[17]; n4 ^= ak_magma_gostf_boxes(p, m[18] ^ m[16], m[17] );
  p = (n4 - mp[m[18]][1]); p += kp[m[18]][1] + m[18]; n3 ^= ak_magma_gostf_boxes(p, m[19] ^ m[17], m[18] );
  p = (n3 - mp[m[19]][2]); p += kp[m[19]][2] + m[19]; n4 ^= ak_magma_gostf_boxes(p, m[20] ^ m[18], m[19] );
  p = (n4 - mp[m[20]][3]); p += kp[m[20]][3] + m[20]; n3 ^= ak_magma_gostf_boxes(p, m[21] ^ m[19], m[20] );
  p = (n3 - mp[m[21]][4]); p += kp[m[21]][4] + m[21]; n4 ^= ak_magma_gostf_boxes(p, m[22] ^ m[20], m[21] );
  p = (n4 - mp[m[22]][5]); p += kp[m[22]][5] + m[22]; n3 ^= ak_magma_gostf_boxes(p, m[23] ^ m[21], m[22] );
  p = (n3 - mp[m[23]][6]); p += kp[m[23]][6] + m[23]; n4 ^= ak_magma_gostf_boxes(p, m[24] ^ m[22], m[23] );
  p = (n4 - mp[m[24]][7]); p += kp[m[24]][7] + m[24]; n3 ^= ak_magma_gostf_boxes(p, m[25] ^ m[23], m[24] );

  p = (n3 - mp[m[25]][0]); p += kp[m[25]][0] + m[25]; n4 ^= ak_magma_gostf_boxes(p, m[26] ^ m[24], m[25] );
  p = (n4 - mp[m[26]][1]); p += kp[m[26]][1] + m[26]; n3 ^= ak_magma_gostf_boxes(p, m[27] ^ m[25], m[26] );
  p = (n3 - mp[m[27]][2]); p += kp[m[27]][2] + m[27]; n4 ^= ak_magma_gostf_boxes(p, m[28] ^ m[26], m[27] );
  p = (n4 - mp[m[28]][3]); p += kp[m[28]][3] + m[28]; n3 ^= ak_magma_gostf_boxes(p, m[29] ^ m[27], m[28] );
  p = (n3 - mp[m[29]][4]); p += kp[m[29]][4] + m[29]; n4 ^= ak_magma_gostf_boxes(p, m[30] ^ m[28], m[29] );
  p = (n4 - mp[m[30]][5]); p += kp[m[30]][5] + m[30]; n3 ^= ak_magma_gostf_boxes(p, m[31] ^ m[29], m[30] );
  p = (n3 - mp[m[31]][6]); p += kp[m[31]][6] + m[31]; n4 ^= ak_magma_gostf_boxes(p, m[32] ^ m[30], m[31] );
  p = (n4 - mp[m[32]][7]); p += kp[m[32]][7] + m[32]; n3 ^= ak_magma_gostf_boxes(p, m[33] ^ m[31], m[32] );

#ifdef LIBAKRYPT_LITTLE_ENDIAN
  ((ak_uint32 *)out)[0] = n4 ^ (m[32] * 0xffffffff); ((ak_uint32 *)out)[1] = n3;
#else
  ((ak_uint32 *)out)[0] = bswap_32( n4 ) ^ (m[32] * 0xffffffff); ((ak_uint32 *)out)[1] = bswap_32( n3 );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция уничтожения развернутых ключей для маскированной магмы

    В данной функции освобождается память выделенная под дополнительные s-боксы а хранящиеся маски
    и ключи заполняются случайнам мусором

    @param skey Указатель на контекст секретного ключа

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_magma_context_delete_keys (ak_skey skey)
{
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* если ключ был создан, но ему не было присвоено значение, здесь возникнет ошибка */
  if( skey->data != NULL ) {
    ak_ptr_context_wipe( skey->data, sizeof( struct magma_encrypted_keys ), &skey->generator );
    free( skey->data );
    skey->data = NULL;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выработки инвертированного ключа и ключевых масок.

    @param skey Указатель на контекст секретного ключа

    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_magma_context_schedule_keys(ak_skey skey)
{
  int idx, error = ak_error_ok;
  struct magma_encrypted_keys *data = NULL;

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using a null pointer to secret key" );
 /* проверяем целостность ключа */
  if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
 /* удаляем былое */
  if( skey->data != NULL ) ak_magma_context_delete_keys( skey );

  if(( data = ak_libakrypt_aligned_malloc( sizeof( struct magma_encrypted_keys ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );

 /* выставляем флаги того, что память выделена */
  memset( data, 0, sizeof( struct magma_encrypted_keys ));
  skey->data = ( ak_pointer )data;
  skey->flags |= ak_key_flag_data_not_free;

 /* размещаем данные */
  if(( error = ak_random_context_random( &skey->generator, data->inmask, sizeof( data->inmask ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect generation first secret key mask" );

  for( idx = 0; idx < 8; idx++ ) {
     data->inkey[0][idx] = ((ak_uint32 *) skey->key )[idx];               /* скопировали */
     data->inkey[0][idx] += data->inmask[0][idx];                /* наложили новую маску */
     data->inkey[0][idx] -= ((ak_uint32 *) skey->key )[idx + 8];   /* сняли старую маску */
                                /* копирование с одновременным обращением (вычисляем ~k) */
     data->inkey[1][idx] = -data->inkey[0][idx];                 /* скопировали значение */
     data->inkey[1][idx] -= ( 1 - data->inmask[1][idx] );        /* наложили новую маску */
     data->inkey[1][idx] += data->inmask[0][idx];                  /* сняли старую маску */
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Наложение аддитивной в кольце \f$ \mathbb Z_{2^{32}}\f$ маски на ключ.

    Функция рассматривает вектор ключа как последовательность \f$ k_1, \ldots, k_n\f$, состоящую
    из элементов кольца  \f$ \mathbb Z_{2^{32}}\f$. Функция вырабатывает случайный вектор
    \f$ x_1, \ldots, x_n\f$ и заменяет ключевой вектор на последовательность значений
    \f$ k_1 + x_1 \pmod{2^{32}}, \ldots, k_n + x_n \pmod{2^{32}}\f$.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_context_set_mask_additive( ak_skey skey )
{
  ak_uint32 newmask[8];
  size_t idx = 0, jdx = 0;
  int error = ak_error_ok;
  struct magma_encrypted_keys *data = NULL;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
 /* проверяем, установлена ли маска ранее */
  if((( skey->flags)&ak_key_flag_set_mask ) == 0 ) {

   #ifndef LIBAKRYPT_LITTLE_ENDIAN
    /* переворачиваем байты ключа для соответствия little endian */
     for( idx = 0; idx < 8; idx++ )
        ((ak_uint32 *)skey->key)[idx] = bswap_32( ((ak_uint32 *)skey->key)[idx] );
   #endif

    /* создаем маску*/
     if(( error = ak_random_context_random( &skey->generator, skey->key+32, 32 )) != ak_error_ok )
       return ak_error_message( error, __func__ , "wrong random mask generation for key buffer" );

    /* накладываем маску на ключ */
     for( idx = 0; idx < 8; idx++ )
        ((ak_uint32 *) skey->key)[idx] += ((ak_uint32 *) skey->key)[idx+8];

    /* меняем значение флага */
     skey->flags |= ak_key_flag_set_mask;

  } else { /* если маска уже установлена, то мы сменяем ее на новую */

           /* для очень длинных ключей маска не изменяется */ /* выше проверка, что длина маски равна 32!! */
            if(( error = ak_random_context_random( &skey->generator, newmask, 32 )) != ak_error_ok )
              return ak_error_message( error, __func__ ,
                                                  "wrong random mask generation for key buffer" );
           /* меняем маску для вектора, хранящегося в структуре skey */
            for( idx = 0; idx < 8; idx++ ) {
               ((ak_uint32 *) skey->key)[idx] += newmask[idx];
               ((ak_uint32 *) skey->key)[idx] -= ((ak_uint32 *) skey->key)[idx+8];
               ((ak_uint32 *) skey->key)[idx+8] = newmask[idx];
            }
          /* меняем маску для внутреннего представления ключевой информации */
            if(( data = ( struct magma_encrypted_keys *)skey->data ) == NULL ) return error;
            for( jdx = 0; jdx < 2; jdx++ ) {
              if(( error = ak_random_context_random( &skey->generator, newmask, 32 )) != ak_error_ok )
                return ak_error_message( error, __func__ ,
                                                  "wrong random mask generation for key buffer" );
              for( idx = 0; idx < 8; idx++ ) {
                 data->inkey[jdx][idx] += newmask[idx];
                 data->inkey[jdx][idx] -= data->inmask[jdx][idx];
                 data->inmask[jdx][idx] = newmask[idx];
              }
            }
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Снятие аддитивной в кольце \f$ \mathbb Z_{2^{32}}\f$ маски на ключ.

    Функция снимает наложенную ранее маску и оставляет значение ключа в его истинном виде.
    В буффер `mask` помещается нулевое значение.
    @param skey Указатель на контекст секретного ключа.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_context_unmask_additive( ak_skey skey )
{
  size_t idx = 0;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
 /* проверяем, установлена ли маска ранее */
  if( (( skey->flags)&ak_key_flag_set_mask ) == 0 ) return ak_error_ok;

 /* снимаем маску с ключа */
  for( idx = 0; idx < 8; idx++ ) {
     ((ak_uint32 *) skey->key)[idx] -= ((ak_uint32 *) skey->key)[idx + 8];
     ((ak_uint32 *) skey->key)[idx] = 0;
  }

 #ifndef LIBAKRYPT_LITTLE_ENDIAN
   /* делаем обратное переворачивание байт ключа */
   for( idx = 0; idx < 8; idx++ )
      ((ak_uint32 *)skey->key)[idx] = bswap_32( ((ak_uint32 *)skey->key)[idx] );
 #endif

 /* меняем значение флага */
  skey->flags ^= ak_key_flag_set_mask;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление значения контрольной суммы ключа.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_context_set_icode_additive( ak_skey skey )
{
  union {
    ak_uint32 x;
    unsigned short int v[2];
  } x, y;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
 /* в силу аддитивности контрольной суммы,
    мы вычисляем результат последовательно для ключа, а потом для его маски */

  ak_ptr_fletcher32( skey->key, 32, &x.x );
  ak_ptr_fletcher32( skey->key+32, 32, &y.x );
  x.v[0] -= y.v[0]; x.v[1] -= y.v[1];
  skey->icode = x.x;

 /* устанавливаем флаг */
  skey->flags |= ak_key_flag_set_icode;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка значения контрольной суммы ключа.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае совпадения контрольной суммы ключа функция возвращает истину (\ref ak_true).
    В противном случае, возвращается ложь (\ref ak_false).                                         */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_skey_context_check_icode_additive( ak_skey skey )
{
  union {
    ak_uint32 x;
    unsigned short int v[2];
  } x, y;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) { ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
    return ak_false;
  }
  if( skey->key == NULL ) { ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
    return ak_false;
  }
  if( skey->key_size == 0 ) { ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
    return ak_false;
  }

 /* в силу аддитивности контрольной суммы,
    мы вычисляем результат последоватлеьно для ключа, а потом для его маски */
  ak_ptr_fletcher32( skey->key, 32, &x.x );
  ak_ptr_fletcher32( skey->key+32, 32, &y.x );
  x.v[0] -= y.v[0]; x.v[1] -= y.v[1];

  if( skey->icode == x.x ) return ak_true;
    else return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализируете контекст ключа алгоритма блочного шифрования Магма (ГОСТ Р 34.12-2015).
    После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    @param bkey Контекст секретного ключа алгоритма блочного шифрования.

    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_context_create_magma( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context" );

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( error = ak_bckey_context_create( bkey, 32, 8 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

 /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oid_context_find_by_name( "magma" )) == NULL ) {
    error = ak_error_get_value();
    ak_error_message( error, __func__, "wrong search of predefined magma block cipher OID" );
    ak_bckey_context_destroy( bkey );
    return error;
  }

 /* ресурс ключа устанавливается в момент присвоения ключа */

 /* устанавливаем методы */
  bkey->key.set_mask = ak_skey_context_set_mask_additive;
  bkey->key.unmask = ak_skey_context_unmask_additive;
  bkey->key.set_icode = ak_skey_context_set_icode_additive;
  bkey->key.check_icode = ak_skey_context_check_icode_additive;

  bkey->schedule_keys = ak_magma_context_schedule_keys;
  bkey->delete_keys = ak_magma_context_delete_keys;
  bkey->encrypt = ak_magma_encrypt_with_random_walk;
  bkey->decrypt = ak_magma_decrypt_with_random_walk;

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_magma.c  */
/* ----------------------------------------------------------------------------------------------- */
