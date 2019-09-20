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

/* ---------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>
 #include <ak_tools.h>
 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Развернутые раундовые ключи и маски алгоритма Кузнечик.
    \details Массив содержит в себе записанные последовательно следующие ключи и маски
    (последовательно, по 10 ключей из двух 64-х битных слов на каждый ключ)
      - раундовые ключи для алгоритма зашифрования
      - раундовые ключи для алгоритма расшифрования
      - маски для раундовых ключей алгоритма зашифрования
      - маски для раундовых ключей алгоритма расшифрования. */
 typedef ak_uint64 ak_kuznechik_expanded_keys[80];

/* ---------------------------------------------------------------------------------------------- */
 static struct kuznechik_params kuznechik_parameters;

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает два элемента конечного поля \f$\mathbb F_{2^8}\f$, определенного
     согласно ГОСТ Р 34.12-2015.                                                                  */
/* ---------------------------------------------------------------------------------------------- */
 static ak_uint8 ak_bckey_context_kuznechik_mul_gf256( ak_uint8 x, ak_uint8 y )
{
  ak_uint8 z = 0;
  while( y ) {
    if( y&0x1 ) z ^= x;
    x = ((ak_uint8)(x << 1)) ^ ( x & 0x80 ? 0xC3 : 0x00 );
    y >>= 1;
  }
 return z;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает вектор w на матрицу D, результат помещается в вектор x.                */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_matrix_mul_vector( linear_matrix D, ak_uint8 *w, ak_uint8* x )
{
  int i = 0, j = 0;
  for( i = 0; i < 16; i++ ) {
    ak_uint8 z = ak_bckey_context_kuznechik_mul_gf256( D[i][0], w[0] );
    for( j = 1; j < 16; j++ ) z ^= ak_bckey_context_kuznechik_mul_gf256( D[i][j], w[j] );
    x[i] = z;
  }
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция возводит квадратную матрицу в квадрат. */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_bckey_context_kuznechik_square_matrix( linear_matrix a )
{
  linear_matrix c;

 /* умножаем */
  for( int i = 0; i < 16; i++ )
   for( int j = 0; j < 16; j++ ) {
      c[i][j] = 0;
      for( int k = 0; k < 16; k++ )
         c[i][j] ^= ak_bckey_context_kuznechik_mul_gf256( a[i][k], a[k][j] );
   }
 /* копируем */
  for( int i = 0; i < 16; i++ )
   for( int j = 0; j < 16; j++ ) a[i][j] = c[i][j];
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует линейное преобразование L согласно ГОСТ Р 34.12-2015
    (шестнадцать тактов работы линейного регистра сдвига).                                        */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_linear_steps( ak_uint8 *w  )
{
  int i = 0, j = 0;
  for( j = 0; j < 16; j++ ) {
     ak_uint8 z = w[0];
     for( i = 1; i < 16; i++ ) {
        w[i-1] = w[i];
        z ^= ak_bckey_context_kuznechik_mul_gf256( w[i], kuznechik_parameters.reg[i] );
     }
     w[15] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для заданного линейного регистра сдвига, задаваемого набором коэффициентов `reg`,
    функция вычисляет 16-ю степень сопровождающей матрицы.

    \param reg Набор коэффициентов, определябщих линейный регистр сдвига
    \param matrix Сопровождающая матрица
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_generate_matrix( const linear_register reg, linear_matrix matrix )
{
  size_t i = 0;

 /* создаем сопровождающую матрицу */
  memset( matrix, 0, sizeof( linear_matrix ));
  for( i = 1; i < 16; i++ ) matrix[i-1][i] = 0x1;
  for( i = 0; i < 16; i++ ) matrix[15][i] = reg[i];

 /* возводим сопровождающую матрицу в 16-ю степень */
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_invert_matrix( linear_matrix matrix, linear_matrix matrixinv )
{
  ak_uint8 i, j;
 /* некоторый фокус */
  for( i = 0; i < 16; i++ ) {
     for( j = 0; j < 16; j++ ) matrixinv[15-i][15-j] = matrix[i][j];
  }
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_invert_permutation( const sbox pi, sbox pinv )
{
  ak_uint32 idx = 0;
  for( idx = 0; idx < sizeof( sbox ); idx++ ) pinv[pi[idx]] = ( ak_uint8 )idx;
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_init_tables( const linear_register reg,
                                                           const sbox pi, ak_kuznechik_params par )
{
  int i, j, l;
  ak_int64 oc = ak_libakrypt_get_option( "openssl_compability" );

 /* сохраняем необходимое */
  memcpy( par->reg, reg, sizeof( linear_register ));
  memcpy( par->pi, pi, sizeof( sbox ));

 /* вырабатываем матрицы */
  ak_bckey_context_kuznechik_generate_matrix( reg, par->L );
  ak_bckey_context_kuznechik_invert_matrix( par->L, par->Linv );

 /* обращаем таблицы замен */
  ak_bckey_context_kuznechik_invert_permutation( pi, par->pinv );

 /* теперь вырабатываем развернутые таблицы */
  for( i = 0; i < 16; i++ ) {
      for( j = 0; j < 256; j++ ) {
         ak_uint8 b[16], ib[16];
         for( l = 0; l < 16; l++ ) {
             b[l] = ak_bckey_context_kuznechik_mul_gf256( par->L[l][i], par->pi[j] );
            ib[l] = ak_bckey_context_kuznechik_mul_gf256( par->Linv[l][i], par->pinv[j] );
         }
         if( oc ) {
           ak_uint8 ch;
           for( l = 0; l < 8; l++) {
              ch = b[i]; b[i] = b[15-i]; b[15-i] = ch;
              ch = ib[i]; ib[i] = ib[15-i]; ib[15-i] = ch;
           }
         }
         memcpy( par->enc[i][j], b, 16 );
         memcpy( par->dec[i][j], ib, 16 );
      }
  }
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_init_gost_tables( void )
{
  int audit = ak_log_get_level();
  ak_bckey_context_kuznechik_init_tables( gost_lvec, gost_pi, &kuznechik_parameters );

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                              "generation of GOST R 34.12-2015 parameters is Ok" );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                функции для работы с контекстом                                  */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма Кузнечик.
    \param skey Указатель на контекст секретного ключа, содержащего развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_delete_keys( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
  if( skey->data != NULL ) {
   /* теперь очистка и освобождение памяти */
    if(( error = ak_ptr_context_wipe( skey->data, sizeof( ak_kuznechik_expanded_keys ),
                                                             &skey->generator )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect wiping an internal data" );
      memset( skey->data, 0, sizeof( ak_kuznechik_expanded_keys ));
    }
    free( skey->data );
    skey->data = NULL;
  }
 return error;
}

#include <stdio.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма Кузнечик.
    \param skey Указатель на контекст секретного ключа, в который помещаются развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_schedule_keys( ak_skey skey )
{
  ak_uint8 reverse[64];
  int i = 0, j = 0, l = 0, kdx = 2;
  ak_uint64 a0[2], a1[2], c[2], t[2], idx = 0;
  ak_int64 oc = ak_libakrypt_get_option( "openssl_compability" );
  ak_uint64 *ekey = NULL, *mkey = NULL, *dkey = NULL, *xkey = NULL, *rkey = NULL, *lkey = NULL;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( skey->key_size != 32 ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                              "unsupported length of secret key" );
 /* проверяем целостность ключа */
  if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
 /* удаляем былое */
  if( skey->data != NULL ) ak_kuznechik_delete_keys( skey );

 /* далее, по-возможности, выделяем выравненную память */
  if(( skey->data = ak_libakrypt_aligned_malloc( sizeof( ak_kuznechik_expanded_keys ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );
 /* получаем указатели на области памяти */
  ekey = ( ak_uint64 *)skey->data;                  /* 10 прямых раундовых ключей */
  dkey = ( ak_uint64 *)skey->data + 20;           /* 10 обратных раундовых ключей */
  mkey = ( ak_uint64 *)skey->data + 40;   /* 10 масок для прямых раундовых ключей */
  xkey = ( ak_uint64 *)skey->data + 60; /* 10 масок для обратных раундовых ключей */
  if( oc ) { /* разворачиваем ключ в каноническое представление */
    for( i = 0; i < 32; i++ ) {
       reverse[i] = skey->key[31-i];
       reverse[32+i] = skey->key[63-i];
    }
    lkey = ( ak_uint64 *)reverse;
    rkey = ( ak_uint64 *)( reverse + skey->key_size );
  } else {
    lkey = ( ak_uint64 *)skey->key; /* исходный ключ */
    rkey = ( ak_uint64 *)( skey->key + skey->key_size );
  }

 /* за один вызов вырабатываем маски для прямых и обратных ключей */
  skey->generator.random( &skey->generator, mkey, 40*sizeof( ak_uint64 ));

 /* только теперь выполняем алгоритм развертки ключа */
  a0[0] = lkey[0]^rkey[0]; a0[1] = lkey[1]^rkey[1];
  a1[0] = lkey[2]^rkey[2]; a1[1] = lkey[3]^rkey[3];

  ekey[0] = a1[0]^mkey[0]; ekey[1] = a1[1]^mkey[1];
  dkey[0] = a1[0]^xkey[0]; dkey[1] = a1[1]^xkey[1];

  ekey[2] = a0[0]^mkey[2]; ekey[3] = a0[1]^mkey[3];
  ak_kuznechik_matrix_mul_vector( kuznechik_parameters.Linv,
                                            (ak_uint8 *)a0, (ak_uint8 *)( dkey+2 ));
  dkey[2] ^= xkey[2]; dkey[3] ^= xkey[3];

  for( j = 0; j < 4; j++ ) {
     for( i = 0; i < 8; i++ ) {
      #ifdef LIBAKRYPT_LITTLE_ENDIAN
        c[0] = ++idx; /* вычисляем константу алгоритма согласно ГОСТ Р 34.12-2015 */
      #else
        c[0] = bswap_64( ++idx );
      #endif
        c[1] = 0;
        ak_kuznechik_linear_steps(( ak_uint8 *)c );

        t[0] = a1[0] ^ c[0]; t[1] = a1[1] ^ c[1];
        for( l = 0; l < 16; l++ ) ((ak_uint8 *)t)[l] = gost_pi[ ((ak_uint8 *)t)[l]];
        ak_kuznechik_linear_steps(( ak_uint8 *)t );

        t[0] ^= a0[0]; t[1] ^= a0[1];
        a0[0] = a1[0]; a0[1] = a1[1];
        a1[0] = t[0];  a1[1] = t[1];
     }
     kdx += 2;
     ekey[kdx] = a1[0]^mkey[kdx]; ekey[kdx+1] = a1[1]^mkey[kdx+1];
     ak_kuznechik_matrix_mul_vector( kuznechik_parameters.Linv,
                                         ( ak_uint8 *)a1, (ak_uint8 *)( dkey+kdx ));
     dkey[kdx] ^= xkey[kdx]; dkey[kdx+1] ^= xkey[kdx+1];

     kdx += 2;
     ekey[kdx] = a0[0]^mkey[kdx]; ekey[kdx+1] = a0[1]^mkey[kdx+1];
     ak_kuznechik_matrix_mul_vector( kuznechik_parameters.Linv,
                                         ( ak_uint8 *)a0, (ak_uint8 *)( dkey+kdx ));
     dkey[kdx] ^= xkey[kdx]; dkey[kdx+1] ^= xkey[kdx+1];
  }

  if( oc ) { /* теперь инвертируем обратно вычисленные значения */
    ak_uint8 ch, *pe = (ak_uint8 *)ekey, *pm = (ak_uint8 *)mkey;
    for( i = 0; i < 160; i +=16 ) {
       for( j = 0; j < 8; j++ ) {
         ch = pe[i+j]; pe[i+j] = pe[i+15-j]; pe[i+15-j] = ch;
         ch = pm[i+j]; pm[i+j] = pm[i+15-j]; pm[i+15-j] = ch;
       }
    }
    pe = (ak_uint8 *)dkey; pm = (ak_uint8 *)xkey;
    for( i = 0; i < 160; i +=16 ) {
       for( j = 0; j < 8; j++ ) {
         ch = pe[i+j]; pe[i+j] = pe[i+15-j]; pe[i+15-j] = ch;
         ch = pm[i+j]; pm[i+j] = pm[i+15-j]; pm[i+15-j] = ch;
       }
    }
    ak_ptr_context_wipe( reverse, sizeof( reverse ), &skey->generator );
  }

   printf("round keys (from min to max):\n");
   for( i = 0; i < 10; i++ ) {
      ak_uint64 k[2] = { ekey[2*i+0]^mkey[2*i+0], ekey[2*i+1]^mkey[2*i+1] };
      printf("%04x:", 16*i );
      for( j = 0; j < 16; j++ ) printf(" %02x", ((ak_uint8 *)k)[j] );
      printf("\n");
   }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_encrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_uint64 *ekey = ( ak_uint64 *)skey->data;
  ak_uint64 *mkey = ( ak_uint64 *)skey->data + 40;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 s, t, x[2];
  ak_uint8 *b = (ak_uint8 *)x;

  x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];
  while( i < 18 ) {
     x[0] ^= ekey[i]; x[0] ^= mkey[i];
     x[1] ^= ekey[++i]; x[1] ^= mkey[i++];

     t  = kuznechik_parameters.enc[ 0][b[15]][0];
     t ^= kuznechik_parameters.enc[ 1][b[14]][0];
     t ^= kuznechik_parameters.enc[ 2][b[13]][0];
     t ^= kuznechik_parameters.enc[ 3][b[12]][0];
     t ^= kuznechik_parameters.enc[ 4][b[11]][0];
     t ^= kuznechik_parameters.enc[ 5][b[10]][0];
     t ^= kuznechik_parameters.enc[ 6][b[ 9]][0];
     t ^= kuznechik_parameters.enc[ 7][b[ 8]][0];
     t ^= kuznechik_parameters.enc[ 8][b[ 7]][0];
     t ^= kuznechik_parameters.enc[ 9][b[ 6]][0];
     t ^= kuznechik_parameters.enc[10][b[ 5]][0];
     t ^= kuznechik_parameters.enc[11][b[ 4]][0];
     t ^= kuznechik_parameters.enc[12][b[ 3]][0];
     t ^= kuznechik_parameters.enc[13][b[ 2]][0];
     t ^= kuznechik_parameters.enc[14][b[ 1]][0];
     t ^= kuznechik_parameters.enc[15][b[ 0]][0];

     s  = kuznechik_parameters.enc[ 0][b[15]][1];
     s ^= kuznechik_parameters.enc[ 1][b[14]][1];
     s ^= kuznechik_parameters.enc[ 2][b[13]][1];
     s ^= kuznechik_parameters.enc[ 3][b[12]][1];
     s ^= kuznechik_parameters.enc[ 4][b[11]][1];
     s ^= kuznechik_parameters.enc[ 5][b[10]][1];
     s ^= kuznechik_parameters.enc[ 6][b[ 9]][1];
     s ^= kuznechik_parameters.enc[ 7][b[ 8]][1];
     s ^= kuznechik_parameters.enc[ 8][b[ 7]][1];
     s ^= kuznechik_parameters.enc[ 9][b[ 6]][1];
     s ^= kuznechik_parameters.enc[10][b[ 5]][1];
     s ^= kuznechik_parameters.enc[11][b[ 4]][1];
     s ^= kuznechik_parameters.enc[12][b[ 3]][1];
     s ^= kuznechik_parameters.enc[13][b[ 2]][1];
     s ^= kuznechik_parameters.enc[14][b[ 1]][1];
     s ^= kuznechik_parameters.enc[15][b[ 0]][1];

     x[0] = t; x[1] = s;
  }
  x[0] ^= ekey[18]; x[1] ^= ekey[19];
  ((ak_uint64 *)out)[0] = x[0] ^ mkey[18];
  ((ak_uint64 *)out)[1] = x[1] ^ mkey[19];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_decrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_uint64 *dkey = ( ak_uint64 *)skey->data + 20;
  ak_uint64 *xkey = ( ak_uint64 *)skey->data + 60;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 t, s, x[2];
  ak_uint8 *b = ( ak_uint8 *)x;

  x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];
  for( i = 0; i < 16; i++ ) b[i] = gost_pi[b[i]];

  i = 19;
  while( i > 1 ) {
     t  = kuznechik_parameters.dec[ 0][b[ 0]][0];
     t ^= kuznechik_parameters.dec[ 1][b[ 1]][0];
     t ^= kuznechik_parameters.dec[ 2][b[ 2]][0];
     t ^= kuznechik_parameters.dec[ 3][b[ 3]][0];
     t ^= kuznechik_parameters.dec[ 4][b[ 4]][0];
     t ^= kuznechik_parameters.dec[ 5][b[ 5]][0];
     t ^= kuznechik_parameters.dec[ 6][b[ 6]][0];
     t ^= kuznechik_parameters.dec[ 7][b[ 7]][0];
     t ^= kuznechik_parameters.dec[ 8][b[ 8]][0];
     t ^= kuznechik_parameters.dec[ 9][b[ 9]][0];
     t ^= kuznechik_parameters.dec[10][b[10]][0];
     t ^= kuznechik_parameters.dec[11][b[11]][0];
     t ^= kuznechik_parameters.dec[12][b[12]][0];
     t ^= kuznechik_parameters.dec[13][b[13]][0];
     t ^= kuznechik_parameters.dec[14][b[14]][0];
     t ^= kuznechik_parameters.dec[15][b[15]][0];

     s  = kuznechik_parameters.dec[ 0][b[ 0]][1];
     s ^= kuznechik_parameters.dec[ 1][b[ 1]][1];
     s ^= kuznechik_parameters.dec[ 2][b[ 2]][1];
     s ^= kuznechik_parameters.dec[ 3][b[ 3]][1];
     s ^= kuznechik_parameters.dec[ 4][b[ 4]][1];
     s ^= kuznechik_parameters.dec[ 5][b[ 5]][1];
     s ^= kuznechik_parameters.dec[ 6][b[ 6]][1];
     s ^= kuznechik_parameters.dec[ 7][b[ 7]][1];
     s ^= kuznechik_parameters.dec[ 8][b[ 8]][1];
     s ^= kuznechik_parameters.dec[ 9][b[ 9]][1];
     s ^= kuznechik_parameters.dec[10][b[10]][1];
     s ^= kuznechik_parameters.dec[11][b[11]][1];
     s ^= kuznechik_parameters.dec[12][b[12]][1];
     s ^= kuznechik_parameters.dec[13][b[13]][1];
     s ^= kuznechik_parameters.dec[14][b[14]][1];
     s ^= kuznechik_parameters.dec[15][b[15]][1];

     x[0] = t; x[1] = s;

     x[1] ^= dkey[i]; x[1] ^= xkey[i--];
     x[0] ^= dkey[i]; x[0] ^= xkey[i--];
  }
  for( i = 0; i < 16; i++ ) b[i] = gost_pinv[b[i]];

  x[0] ^= dkey[0]; x[1] ^= dkey[1];
  (( ak_uint64 *) out)[0] = x[0] ^ xkey[0];
  (( ak_uint64 *) out)[1] = x[1] ^ xkey[1];
}

/* ----------------------------------------------------------------------------------------------- */
/*! После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    \param bkey Контекст секретного ключа алгоритма блочного шифрования.
    \return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
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
    ak_error_message( error = ak_error_get_value(), __func__,
                                        "wrong search of predefined kuznechik block cipher OID" );
    ak_bckey_context_destroy( bkey );
    return error;
  }

 /* ресурс ключа устанавливается в момент присвоения ключа */

 /* устанавливаем методы */
  bkey->schedule_keys = ak_kuznechik_schedule_keys;
  bkey->delete_keys = ak_kuznechik_delete_keys;
  bkey->encrypt = ak_kuznechik_encrypt_with_mask;
  bkey->decrypt = ak_kuznechik_decrypt_with_mask;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                      функции тестирования                                       */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_bckey_test_kuznechik_parameters( void )
{
  struct hash ctx;
  ak_uint8 out[16];
  struct kuznechik_params parameters;
  int error = ak_error_ok, audit = ak_log_get_level();

  ak_uint8 esum[16] = { 0x5B, 0x80, 0x54, 0xB3, 0x4E, 0x81, 0x09, 0x94,
                        0xCC, 0x83, 0x8B, 0x8E, 0x53, 0xBA, 0x9D, 0x18 };
  ak_uint8 dsum[16] = { 0xBF, 0x07, 0xDF, 0x13, 0x1E, 0x30, 0xCD, 0xA1,
                        0x26, 0x14, 0xBA, 0x2C, 0xFB, 0x28, 0xEC, 0xA3 };

 /* вырабатываем значения параметров */
  ak_bckey_context_kuznechik_init_tables( gost_lvec, gost_pi, &parameters );

 /* проверяем генерацию обратной перестановки */
  if( !ak_ptr_is_equal_with_log( parameters.pinv, gost_pinv, sizeof( sbox ))) {
    ak_error_message( ak_error_not_equal_data, __func__,
                                         "incorrect generation of nonlinear inverse permutation" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                                     "inverse permutation is Ok" );

 /* проверяем генерацию сопровождающей матрицы линейного регистра сдвига и обратной к ней */
  if( !ak_ptr_is_equal( parameters.L, gost_L, sizeof( linear_matrix ))) {
    size_t i = 0;
    ak_error_message( ak_error_not_equal_data, __func__,
                                              "incorrect generation of linear reccurence matrix" );
    ak_error_message( 0, __func__, "matrix:" );
    for( i = 0; i < 16; i++ ) {
      ak_error_message_fmt( 0, __func__,
        "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        parameters.L[i][0],  parameters.L[i][1],  parameters.L[i][2],  parameters.L[i][3],
        parameters.L[i][4],  parameters.L[i][5],  parameters.L[i][6],  parameters.L[i][7],
        parameters.L[i][8],  parameters.L[i][9],  parameters.L[i][10], parameters.L[i][11],
              parameters.L[i][12], parameters.L[i][13], parameters.L[i][14], parameters.L[i][15] );
    }
    return ak_false;
  }

  if( !ak_ptr_is_equal( parameters.Linv, gost_Linv, sizeof( linear_matrix ))) {
    size_t i = 0;
    ak_error_message( ak_error_not_equal_data, __func__,
                                              "incorrect generation inverse of companion matrix" );
    ak_error_message( 0, __func__, "inverse matrix:" );
    for( i = 0; i < 16; i++ ) {
      ak_error_message_fmt( 0, __func__,
        "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        parameters.Linv[i][0],  parameters.Linv[i][1],  parameters.Linv[i][2],
        parameters.Linv[i][3],  parameters.Linv[i][4],  parameters.Linv[i][5],
        parameters.Linv[i][6],  parameters.Linv[i][7],  parameters.Linv[i][8],
        parameters.Linv[i][9],  parameters.Linv[i][10], parameters.Linv[i][11],
        parameters.Linv[i][12], parameters.Linv[i][13], parameters.Linv[i][14],
                                                                          parameters.Linv[i][15] );
    }
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                       "companion matrix and it's inverse is Ok" );
 /* проверяем выработанные таблицы */
  if(( error = ak_hash_context_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of hash function context" );
    return ak_false;
  }
  ak_hash_context_ptr( &ctx, parameters.enc, sizeof( expanded_table ), out, sizeof( out ));
  if( !ak_ptr_is_equal_with_log( out, esum, sizeof( out ))) {
    ak_hash_context_destroy( &ctx );
    ak_error_message( ak_error_not_equal_data, __func__,
                                                      "incorrect hash value of encryption table" );
    return ak_false;
  }

  ak_hash_context_ptr( &ctx, parameters.dec, sizeof( expanded_table ), out, sizeof( out ));
  if( !ak_ptr_is_equal_with_log( out, dsum, sizeof( out ))) {
    ak_hash_context_destroy( &ctx );    
    ak_error_message( ak_error_not_equal_data, __func__,
                                                      "incorrect hash value of encryption table" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                   "expanded encryption/decryption tables is Ok" );
  ak_hash_context_destroy( &ctx );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_bckey_test_kuznechik( void )
{
  int audit = audit = ak_log_get_level();

 /* тестируем стандартные параметры алгоритма */
  if( !ak_bckey_test_kuznechik_parameters( )) {
    ak_error_message( ak_error_get_value(), __func__,
                             "incorrect testing of predefined parameters from GOST R 34.12-2015" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                 "testing of predefined parameters from GOST R 34.12-2015 is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_kuznechik.c  */
/* ----------------------------------------------------------------------------------------------- */
