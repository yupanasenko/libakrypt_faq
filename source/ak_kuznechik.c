/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_kuznechik.h                                                                            */
/*  - содержит реализацию алгоритма блочного шифрования Кузнечик,                                  */
/*    регламентированного ГОСТ Р 34.12-2015                                                        */
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
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
 #include <wmmintrin.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>
 #include <ak_bckey.h>
 #include <ak_parameters.h>

/* ---------------------------------------------------------------------------------------------- */
 static ak_uint128 kuz_mat_enc128[16][256];
 static ak_uint128 kuz_mat_dec128[16][256];

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает два элемента конечного поля \f$\mathbb F_{2^8}\f$, определенного
     согласно ГОСТ Р 34.12-2015.                                                                  */
/* ---------------------------------------------------------------------------------------------- */
 static ak_uint8 ak_kuznechik_mul_gf256( ak_uint8 x, ak_uint8 y )
{
  ak_uint8 z = 0;
  while (y) {
    if (y & 1) z ^= x;
      x = (x << 1) ^ ( x & 0x80 ? 0xC3 : 0x00 );
      y >>= 1;
  }
 return z;
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует линейное преобразование L согласно ГОСТ Р 34.12-2015
    (шестнадцать тактов работы линейного регистра сдвига).                                        */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_linear_steps( ak_uint128 *w  )
{
  int i = 0, j = 0;
  const ak_uint8 kuz_lvec[16] = {
   0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94
  };

  for( j = 0; j < 16; j++ ) {
     ak_uint8 z = w->b[0];
     for( i = 1; i < 16; i++ ) {
        w->b[i-1] = w->b[i];
        z ^= ak_kuznechik_mul_gf256( w->b[i], kuz_lvec[i] );
     }
     w->b[15] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает вектор w на матрицу D, результат помещается в вектор x.                */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_matrix_mul_vector( const ak_uint8 D[16][16],
                                                                      ak_uint128 *w, ak_uint128* x )
{
  int i = 0, j = 0;
  for( i = 0; i < 16; i++ ) {
    ak_uint8 z = ak_kuznechik_mul_gf256( D[i][0], w->b[0] );
    for( j = 1; j < 16; j++ ) z ^= ak_kuznechik_mul_gf256( D[i][j], w->b[j] );
    x->b[i] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_init_kuznechik_tables( void )
{
  int i, j, l;
  for( i = 0; i < 16; i++ ) {
      for( j = 0; j < 256; j++ ) {
         for( l = 0; l < 16; l++ ) {
            kuz_mat_enc128[i][j].b[l] = ak_kuznechik_mul_gf256( L[l][i], gost_pi[j] );
            kuz_mat_dec128[i][j].b[l] = ak_kuznechik_mul_gf256( Linv[l][i], gost_pinv[j] );
         }
      }
  }

 if( ak_log_get_level() != ak_log_none )
   ak_error_message( ak_error_ok, __func__ , "initialization of predefined tables is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Раундовые ключи алгоритма Кузнечик. */
 struct
#ifndef _MSC_VER
  __attribute__((aligned(16)))
#else
  __declspec(align(16))
#endif
 kuznechik_expanded_keys {
  ak_uint128 k[10];
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура с внутренними данными секретного ключа алгоритма Кузнечик. */
 struct
#ifndef _MSC_VER
  __attribute__((aligned(16)))
#else
  __declspec(align(16))
#endif
 kuznechik {
  /*! \brief раундовые ключи для алгоритма зашифрования */
  struct kuznechik_expanded_keys encryptkey;
  /*! \brief раундовые ключи для алгоритма расшифрования */
  struct kuznechik_expanded_keys decryptkey;
  /*! \brief маски для раундовых ключей алгоритма зашифрования */
  struct kuznechik_expanded_keys encryptmask;
  /*! \brief маски для раундовых ключей алгоритма расшифрования */
  struct kuznechik_expanded_keys decryptmask;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма Кузнечик. */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_delete_keys( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
  if( skey->data == NULL ) return ak_error_message( ak_error_null_pointer,
                                   __func__ , "using a null pointer to secret key internal data" );
 /* теперь очистка и освобождение памяти */
  if(( error = ak_random_context_random( &skey->generator,
                                   skey->data, sizeof( struct kuznechik ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect wiping an internal data" );
    memset( skey->data, 0, sizeof ( struct kuznechik ));
  }
  if( skey->data != NULL ) {
    free( skey->data );
    skey->data = NULL;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма Кузнечик. */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_schedule_keys( ak_skey skey )
{
  ak_uint128 a0, a1, c, t;
  struct kuznechik_expanded_keys *ekey = NULL, *mkey = NULL;
  struct kuznechik_expanded_keys *dkey = NULL, *xkey = NULL;
  int i = 0, j = 0, l = 0, idx = 0, kdx = 1;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* проверяем целостность ключа */
  if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
 /* удаляем былое */
  if( skey->data != NULL ) ak_kuznechik_delete_keys( skey );

 /* готовим память для переменных */
  if(( skey->data = /* далее, по-возможности, выделяем выравненную память */
                  ak_libakrypt_aligned_malloc( sizeof( struct kuznechik ))) == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );
 /* получаем указатели на области памяти */
  ekey = &(( struct kuznechik * ) skey->data )->encryptkey;
  mkey = &(( struct kuznechik * ) skey->data )->encryptmask;
  dkey = &(( struct kuznechik * ) skey->data )->decryptkey;
  xkey = &(( struct kuznechik * ) skey->data )->decryptmask;

 /* вырабатываем маски */
  skey->generator.random( &skey->generator, mkey, sizeof( struct kuznechik_expanded_keys ));
  skey->generator.random( &skey->generator, xkey, sizeof( struct kuznechik_expanded_keys ));

 /* только теперь выполняем алгоритм развертки ключа */
  a0.q[0] = (( ak_uint128 *) skey->key.data )[0].q[0] ^ (( ak_uint128 *) skey->mask.data )[0].q[0];
  a0.q[1] = (( ak_uint128 *) skey->key.data )[0].q[1] ^ (( ak_uint128 *) skey->mask.data )[0].q[1];
  a1.q[0] = (( ak_uint128 *) skey->key.data )[1].q[0] ^ (( ak_uint128 *) skey->mask.data )[1].q[0];
  a1.q[1] = (( ak_uint128 *) skey->key.data )[1].q[1] ^ (( ak_uint128 *) skey->mask.data )[1].q[1];

  ekey->k[0].q[0] = a1.q[0]^mkey->k[0].q[0];
  dkey->k[0].q[0] = a1.q[0]^xkey->k[0].q[0];

  ekey->k[0].q[1] = a1.q[1]^mkey->k[0].q[1];
  dkey->k[0].q[1] = a1.q[1]^xkey->k[0].q[1];

  ekey->k[1].q[0] = a0.q[0]^mkey->k[1].q[0];
  ekey->k[1].q[1] = a0.q[1]^mkey->k[1].q[1];

  ak_kuznechik_matrix_mul_vector( Linv, &a0, &dkey->k[1] );
  dkey->k[1].q[0] ^= xkey->k[1].q[0]; dkey->k[1].q[1] ^= xkey->k[1].q[1];

  for( j = 0; j < 4; j++ ) {
     for( i = 0; i < 8; i++ ) {
      #ifdef LIBAKRYPT_LITTLE_ENDIAN
        c.q[0] = ++idx; /* вычисляем константу алгоритма согласно ГОСТ Р 34.12-2015 */
      #else
        c.q[0] = bswap_64( ++idx );
      #endif
        c.q[1] = 0;
        ak_kuznechik_linear_steps( &c );

        t.q[0] = a1.q[0] ^ c.q[0]; t.q[1] = a1.q[1] ^ c.q[1];
        for( l = 0; l < 16; l++ ) t.b[l] = gost_pi[t.b[l]];
        ak_kuznechik_linear_steps( &t );

        t.q[0] ^= a0.q[0]; t.q[1] ^= a0.q[1];
        a0.q[0] = a1.q[0]; a0.q[1] = a1.q[1];
        a1.q[0] = t.q[0];  a1.q[1] = t.q[1];
     }
     kdx++;
     ekey->k[kdx].q[0] = a1.q[0]^mkey->k[kdx].q[0];
     ekey->k[kdx].q[1] = a1.q[1]^mkey->k[kdx].q[1];
     ak_kuznechik_matrix_mul_vector( Linv, &a1, &dkey->k[kdx] );
     dkey->k[kdx].q[0] ^= xkey->k[kdx].q[0];
     dkey->k[kdx].q[1] ^= xkey->k[kdx].q[1];

     kdx++;
     ekey->k[kdx].q[0] = a0.q[0]^mkey->k[kdx].q[0];
     ekey->k[kdx].q[1] = a0.q[1]^mkey->k[kdx].q[1];
     ak_kuznechik_matrix_mul_vector( Linv, &a0, &dkey->k[kdx] );
     dkey->k[kdx].q[0] ^= xkey->k[kdx].q[0];
     dkey->k[kdx].q[1] ^= xkey->k[kdx].q[1];
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменяет маску ключа алгоритма блочного шифрования Кузнечик.                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_set_mask_xor( ak_skey skey )
{
  size_t idx = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки длин и указателей */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );
  if( skey->key.size != 32 ) ak_error_message( ak_error_wrong_key_length, __func__ ,
                                                    "using a secret key with unexpected length" );
 /* проверяем, установлена ли маска ранее */
  if( (( skey->flags)&skey_flag_set_mask ) == 0 ) {
    /* создаем маску*/
     if(( error = ak_random_context_random( &skey->generator,
                                             skey->mask.data, skey->mask.size )) != ak_error_ok )
       return ak_error_message( error, __func__ , "wrong random mask generation for key buffer" );
    /* накладываем маску на ключ */
     for( idx = 0; idx < skey->key.size; idx++ )
        ((ak_uint8 *) skey->key.data)[idx] ^= ((ak_uint8 *) skey->mask.data)[idx];
    /* меняем значение флага */
     skey->flags |= skey_flag_set_mask;

  } else { /* если маска уже установлена, то мы ее сменяем */
            ak_uint64 mask[20], *kptr = NULL, *mptr = NULL;

            if(( error = ak_random_context_random( &skey->generator,
                                                         mask, skey->key.size )) != ak_error_ok )
              return ak_error_message( error, __func__, "wrong generation random key mask");

            for( idx = 0; idx < 4; idx++ ) {
               ((ak_uint64 *) skey->key.data)[idx] ^= mask[idx];
               ((ak_uint64 *) skey->key.data)[idx] ^= ((ak_uint64 *) skey->mask.data)[idx];
               ((ak_uint64 *) skey->mask.data)[idx] = mask[idx];
            }

           /* перемаскируем раундовые ключи зашифрования */
            if(( error = ak_random_context_random( &skey->generator,
                                                  mask, 20*sizeof( ak_uint64 ))) != ak_error_ok )
              return ak_error_message( error, __func__, "wrong generation random key mask");

            kptr = (ak_uint64 *) ( &(( struct kuznechik *)skey->data)->encryptkey );
            mptr = (ak_uint64 *) ( &(( struct kuznechik *)skey->data)->encryptmask );
            for( idx = 0; idx < 20; idx++ ) {
               kptr[idx] ^= mask[idx]; kptr[idx] ^= mptr[idx]; mptr[idx] = mask[idx];
            }

           /* перемаскируем раундовые ключи расшифрования */
            if(( error = ak_random_context_random( &skey->generator,
                                                  mask, 20*sizeof( ak_uint64 ))) != ak_error_ok )
              return ak_error_message( error, __func__, "wrong generation random key mask");

            kptr = (ak_uint64 *) ( &(( struct kuznechik *)skey->data)->decryptkey );
            mptr = (ak_uint64 *) ( &(( struct kuznechik *)skey->data)->decryptmask );
            for( idx = 0; idx < 20; idx++ ) {
               kptr[idx] ^= mask[idx]; kptr[idx] ^= mptr[idx]; mptr[idx] = mask[idx];
            }

           /* удаляем старое */
            memset( mask, 0, 20*sizeof( ak_uint64 ));
         }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_encrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  struct kuznechik_expanded_keys *ekey = &(( struct kuznechik * ) skey->data )->encryptkey;
  struct kuznechik_expanded_keys *mkey = &(( struct kuznechik * ) skey->data )->encryptmask;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 t;
  ak_uint128 x;
  x.q[0] = (( ak_uint64 *) in)[0]; x.q[1] = (( ak_uint64 *) in)[1];

  for( i = 0; i < 9; i++ ) {
     x.q[0] ^= ekey->k[i].q[0]; x.q[0] ^= mkey->k[i].q[0];
     x.q[1] ^= ekey->k[i].q[1]; x.q[1] ^= mkey->k[i].q[1];

     t = kuz_mat_enc128[ 0][x.b[ 0]].q[0] ^
         kuz_mat_enc128[ 1][x.b[ 1]].q[0] ^
         kuz_mat_enc128[ 2][x.b[ 2]].q[0] ^
         kuz_mat_enc128[ 3][x.b[ 3]].q[0] ^
         kuz_mat_enc128[ 4][x.b[ 4]].q[0] ^
         kuz_mat_enc128[ 5][x.b[ 5]].q[0] ^
         kuz_mat_enc128[ 6][x.b[ 6]].q[0] ^
         kuz_mat_enc128[ 7][x.b[ 7]].q[0] ^
         kuz_mat_enc128[ 8][x.b[ 8]].q[0] ^
         kuz_mat_enc128[ 9][x.b[ 9]].q[0] ^
         kuz_mat_enc128[10][x.b[10]].q[0] ^
         kuz_mat_enc128[11][x.b[11]].q[0] ^
         kuz_mat_enc128[12][x.b[12]].q[0] ^
         kuz_mat_enc128[13][x.b[13]].q[0] ^
         kuz_mat_enc128[14][x.b[14]].q[0] ^
         kuz_mat_enc128[15][x.b[15]].q[0];

     x.q[1] = kuz_mat_enc128[ 0][x.b[ 0]].q[1] ^
         kuz_mat_enc128[ 1][x.b[ 1]].q[1] ^
         kuz_mat_enc128[ 2][x.b[ 2]].q[1] ^
         kuz_mat_enc128[ 3][x.b[ 3]].q[1] ^
         kuz_mat_enc128[ 4][x.b[ 4]].q[1] ^
         kuz_mat_enc128[ 5][x.b[ 5]].q[1] ^
         kuz_mat_enc128[ 6][x.b[ 6]].q[1] ^
         kuz_mat_enc128[ 7][x.b[ 7]].q[1] ^
         kuz_mat_enc128[ 8][x.b[ 8]].q[1] ^
         kuz_mat_enc128[ 9][x.b[ 9]].q[1] ^
         kuz_mat_enc128[10][x.b[10]].q[1] ^
         kuz_mat_enc128[11][x.b[11]].q[1] ^
         kuz_mat_enc128[12][x.b[12]].q[1] ^
         kuz_mat_enc128[13][x.b[13]].q[1] ^
         kuz_mat_enc128[14][x.b[14]].q[1] ^
         kuz_mat_enc128[15][x.b[15]].q[1];
     x.q[0] = t;
  }
  x.q[0] ^= ekey->k[9].q[0]; x.q[1] ^= ekey->k[9].q[1];
  ((ak_uint64 *)out)[0] = x.q[0] ^ mkey->k[9].q[0];
  ((ak_uint64 *)out)[1] = x.q[1] ^ mkey->k[9].q[1];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_decrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  struct kuznechik_expanded_keys *dkey = &(( struct kuznechik * ) skey->data )->decryptkey;
  struct kuznechik_expanded_keys *xkey = &(( struct kuznechik * ) skey->data )->decryptmask;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 t;
  ak_uint128 x;

  x.q[0] = (( ak_uint64 *) in)[0]; x.q[1] = (( ak_uint64 *) in)[1];
  for( i = 0; i < 16; i++ ) x.b[i] = gost_pi[x.b[i]];
  for( i = 9; i > 0; i-- ) {
     t = kuz_mat_dec128[ 0][x.b[ 0]].q[0] ^
         kuz_mat_dec128[ 1][x.b[ 1]].q[0] ^
         kuz_mat_dec128[ 2][x.b[ 2]].q[0] ^
         kuz_mat_dec128[ 3][x.b[ 3]].q[0] ^
         kuz_mat_dec128[ 4][x.b[ 4]].q[0] ^
         kuz_mat_dec128[ 5][x.b[ 5]].q[0] ^
         kuz_mat_dec128[ 6][x.b[ 6]].q[0] ^
         kuz_mat_dec128[ 7][x.b[ 7]].q[0] ^
         kuz_mat_dec128[ 8][x.b[ 8]].q[0] ^
         kuz_mat_dec128[ 9][x.b[ 9]].q[0] ^
         kuz_mat_dec128[10][x.b[10]].q[0] ^
         kuz_mat_dec128[11][x.b[11]].q[0] ^
         kuz_mat_dec128[12][x.b[12]].q[0] ^
         kuz_mat_dec128[13][x.b[13]].q[0] ^
         kuz_mat_dec128[14][x.b[14]].q[0] ^
         kuz_mat_dec128[15][x.b[15]].q[0];

     x.q[1] = kuz_mat_dec128[ 0][x.b[ 0]].q[1] ^
         kuz_mat_dec128[ 1][x.b[ 1]].q[1] ^
         kuz_mat_dec128[ 2][x.b[ 2]].q[1] ^
         kuz_mat_dec128[ 3][x.b[ 3]].q[1] ^
         kuz_mat_dec128[ 4][x.b[ 4]].q[1] ^
         kuz_mat_dec128[ 5][x.b[ 5]].q[1] ^
         kuz_mat_dec128[ 6][x.b[ 6]].q[1] ^
         kuz_mat_dec128[ 7][x.b[ 7]].q[1] ^
         kuz_mat_dec128[ 8][x.b[ 8]].q[1] ^
         kuz_mat_dec128[ 9][x.b[ 9]].q[1] ^
         kuz_mat_dec128[10][x.b[10]].q[1] ^
         kuz_mat_dec128[11][x.b[11]].q[1] ^
         kuz_mat_dec128[12][x.b[12]].q[1] ^
         kuz_mat_dec128[13][x.b[13]].q[1] ^
         kuz_mat_dec128[14][x.b[14]].q[1] ^
         kuz_mat_dec128[15][x.b[15]].q[1];

      x.q[0] = t;
      x.q[0] ^= dkey->k[i].q[0]; x.q[1] ^= dkey->k[i].q[1];
      x.q[0] ^= xkey->k[i].q[0]; x.q[1] ^= xkey->k[i].q[1];
  }
  for( i = 0; i < 16; i++ ) x.b[i] = gost_pinv[x.b[i]];

  x.q[0] ^= dkey->k[0].q[0]; x.q[1] ^= dkey->k[0].q[1];
  (( ak_uint64 *) out)[0] = x.q[0] ^ xkey->k[0].q[0];
  (( ak_uint64 *) out)[1] = x.q[1] ^ xkey->k[0].q[1];
}

/* ----------------------------------------------------------------------------------------------- */
/*! После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    @param bkey Контекст секретного ключа алгоритма блочного шифрования.

    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_create_kuznechik( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context" );

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( error = ak_bckey_context_create( bkey, 32, 16 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

 /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oid_context_find_by_name( "kuznechik" )) == NULL ) {
    error = ak_error_get_value();
    ak_error_message( error, __func__, "wrong search of predefined kuznechik block cipher OID" );
    ak_bckey_context_destroy( bkey );
    return error;
  };

 /* устанавливаем ресурс использования серетного ключа */
  bkey->key.resource.counter = ak_libakrypt_get_option( "kuznechik_cipher_resource" );

 /* устанавливаем методы */
  bkey->key.set_mask =  ak_kuznechik_set_mask_xor;

  bkey->schedule_keys = ak_kuznechik_schedule_keys;
  bkey->delete_keys = ak_kuznechik_delete_keys;
  bkey->encrypt = ak_kuznechik_encrypt_with_mask;
  bkey->decrypt = ak_kuznechik_decrypt_with_mask;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Тестирование производится в соответствии с ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015.              */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_test_kuznechik( void )
{
  char *str = NULL;
  struct bckey bkey;
  ak_bool result = ak_true;
  int error = ak_error_ok, audit = ak_log_get_level();

 /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.1 */
 /* тестовый ключ из ГОСТ Р 34.13-2015, приложение А.1 */
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 /* открытый текст из ГОСТ Р 34.12-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint8 in[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };

 /* зашифрованный блок из ГОСТ Р 34.12-2015 */
  ak_uint8 out[16] = {
    0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a, 0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f };

 /* открытый текст из ГОСТ Р 34.13-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint8 inlong[64] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22 };

  ak_uint8 outecb[64] = {
    0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a, 0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f,
    0x8b, 0xd0, 0x18, 0x67, 0xd7, 0x52, 0x54, 0x28, 0xf9, 0x32, 0x00, 0x6e, 0x2c, 0x91, 0x29, 0xb4,
    0x57, 0xb1, 0xd4, 0x3b, 0x31, 0xa5, 0xf5, 0xf3, 0xee, 0x7c, 0x24, 0x9d, 0x54, 0x33, 0xca, 0xf0,
    0x98, 0xda, 0x8a, 0xaa, 0xc5, 0xc4, 0x02, 0x3a, 0xeb, 0xb9, 0x30, 0xe8, 0xcd, 0x9c, 0xb0, 0xd0 };

 /* инициализационный вектор для режима гаммирования (счетчика) */
  ak_uint8 ivctr[8] = { 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12 };

 /* результат зашифрования в режиме гаммирования (счетчика) */
  ak_uint8 outctr[64] = {
    0xb8, 0xa1, 0xbd, 0x40, 0xa2, 0x5f, 0x7b, 0xd5, 0xdb, 0xd1, 0x0e, 0xc1, 0xbe, 0xd8, 0x95, 0xf1,
    0xe4, 0xde, 0x45, 0x3c, 0xb3, 0xe4, 0x3c, 0xf3, 0x5d, 0x3e, 0xa1, 0xf6, 0x33, 0xe7, 0xee, 0x85,
    0xa5, 0xa3, 0x64, 0x35, 0xf1, 0x77, 0xe8, 0xd5, 0xd3, 0x6e, 0x35, 0xe6, 0x8b, 0xe8, 0xea, 0xa5,
    0x73, 0xba, 0xbd, 0x20, 0x58, 0xd1, 0xc6, 0xd1, 0xb6, 0xba, 0x0c, 0xf2, 0xb1, 0xfa, 0x91, 0xcb };

  ak_uint8 xiv1[8] = { 0x61, 0x2D, 0x93, 0x42, 0xAE, 0x2E, 0x57, 0x21 };
  ak_uint8 xin1[23] = {
    0x31, 0xEA, 0x54, 0xBB, 0xB7, 0xE5, 0xE5, 0x1C, 0xAE, 0xEB, 0x79, 0x28, 0x71, 0x5E, 0x93, 0xFF,
    0x9B, 0x8D, 0xD4, 0x90, 0xC4, 0x76, 0xBC };
  ak_uint8 xout1[23] = {
    0x30, 0xF6, 0x0A, 0xA9, 0xC0, 0x11, 0x77, 0xCE, 0xCD, 0xE9, 0x40, 0x9A, 0x4B, 0x46, 0x1C, 0x64,
    0xF6, 0xCA, 0xF7, 0xC6, 0x90, 0x18, 0x65 };

 /* значение имитовставки согласно ГОСТ Р 34.13-2015 (раздел А.1.6) */
  ak_uint8 imito[16] = {
     0x67, 0x9C, 0x74, 0x37, 0x5B, 0xB3, 0xDE, 0x4D, 0xE3, 0xFB, 0x59, 0x60, 0x29, 0x4D, 0x6F, 0x33 };

 /* временный буффер */
  ak_uint8 myout[64];

 /* 1. Создаем контекст ключа алгоритма Кузнечик и устанавливаем значение ключа */
  if(( error = ak_bckey_context_create_kuznechik( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
    return ak_false;
  }

  if(( error = ak_bckey_context_set_key( &bkey, testkey, sizeof( testkey ), ak_false )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong creation of test key" );
    result = ak_false;
    goto exit;
  }

 /* 2. Тестируем зашифрование/расшифрование одного блока согласно ГОСТ Р34.12-2015 */
  bkey.encrypt( &bkey.key, in, myout );
  if( !ak_ptr_is_equal( myout, out, 16 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                       "the one block encryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the one block encryption test from GOST R 34.12-2015 is Ok" );

  bkey.decrypt( &bkey.key, out, myout );
  if( !ak_ptr_is_equal( myout, in, 16 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                       "the one block decryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( in, 16, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the one block decryption test from GOST R 34.12-2015 is Ok" );

 /* 3. Тестируем режим простой замены согласно ГОСТ Р34.13-2015 */
  if(( error = ak_bckey_context_encrypt_ecb( &bkey, inlong, myout, 64 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong ecb mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, outecb, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the ecb mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outecb, 64, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }

  if(( error = ak_bckey_context_decrypt_ecb( &bkey, outecb, myout, 64 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong ecb mode decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, inlong, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the ecb mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                "the ecb mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* 4. Тестируем режим гаммирования (счетчика) согласно ГОСТ Р34.13-2015 */
  if(( error = ak_bckey_context_xcrypt( &bkey, inlong, myout, 64, ivctr, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong counter mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, outctr, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the counter mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outctr, 64, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }

  if(( error = ak_bckey_context_xcrypt( &bkey, outctr, myout, 64, ivctr, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong counter mode decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, inlong, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the counter mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
               "the counter mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* 5. Тестируем режим гаммирования (счетчика) на длинах, не кратных длине блока. */
  if( ak_bckey_context_xcrypt( &bkey, xin1, myout, 23, xiv1, 8 ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong plain text encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, xout1, 23 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                        "the counter mode encryption test for 23 octets is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 23, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( xout1, 23, ak_false )); free(str);
    result = ak_false;
    goto exit;
  }

  if( ak_bckey_context_xcrypt( &bkey, xout1, myout, 23, xiv1, 8 ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong cipher text decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, xin1, 23 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                        "the counter mode decryption test for 23 octets is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 23, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( xin1, 23, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                               "the counter mode encryption/decryption test for 23 octets is Ok" );

 /* 6. Тестируем режим выработки имитовставки (плоская реализация). */
  ak_bckey_context_omac( &bkey, inlong, sizeof( inlong ), myout );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong omac calculation" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal( myout, imito, 16 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                   "the omac integrity mode test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( imito, 16, ak_true )); free( str );
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "the omac integrity mode test from GOST R 34.13-2015 is Ok" );
 /* освобождаем ключ и выходим */
  exit:
  if(( error = ak_bckey_context_destroy( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong destroying of secret key" );
    return ak_false;
  }

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_kuznechik.c  */
/* ----------------------------------------------------------------------------------------------- */
