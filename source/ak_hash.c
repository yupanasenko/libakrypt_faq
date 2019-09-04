/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hash.c                                                                                 */
/*  - содержит реализацию алгоритмов итерационного сжатия                                          */
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
 #include <ak_hash.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
/*                            Реализация функции хеширования Стрибог                               */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование LPS.
 *  \details \note Мы предполагаем, что данные содержат 64 байта.                                  */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_lps( ak_uint64 *result, const ak_uint64 *data )
{
  size_t idx = 0, idx2 = 0;
  const unsigned char *a = ( const unsigned char*) data; /* приводим к массиву байт */

  /* Все три преобразования вместе                           */
  /* (этот очень короткий код был предложен Павлом Лебедевым */
  for( idx = 0; idx < 8; idx++ ) {
    ak_uint64 sidx = idx, c = 0;
    for( idx2 = 0; idx2 < 8; idx2++, sidx += 8 ) {
      c ^= streebog_Areverse_expand[idx2][gost_pi[a[sidx]]];
    }
    result[idx] = c;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование X.
 *  \details \note Мы предполагаем, что данные содержат 64 байта.                                  */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_x( ak_uint64 *r, const ak_uint64 *k, const ak_uint64 *a )
{
  int idx = 0;
  for( idx = 0; idx < 8; idx++ ) r[idx] = k[idx] ^ a[idx];
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование G
 *  \details\note Мы предполагаем, что массивы n и m содержат по 64 байта.                         */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_g( ak_streebog ctx, ak_uint64 *n, const ak_uint64 *m )
{
   int idx = 0;
   ak_uint64 K[8], T[8], B[8];

       if( n != NULL ) {
         ak_hash_context_streebog_x( B, ctx->h, n );
         ak_hash_context_streebog_lps( K, B );
       }
        else
         ak_hash_context_streebog_lps( K, ctx->h );

       /* K - ключ K1 */
       for( idx = 0; idx < 8; idx++ ) T[idx] = m[idx]; /* memcpy( T, m, 64 ); */

       for( idx = 0; idx < 12; idx++ ) {
          ak_hash_context_streebog_x( B, T, K );
          ak_hash_context_streebog_lps( T, B ); /* преобразуем текст */

          ak_hash_context_streebog_x( B, K, streebog_c[idx] );
          ak_hash_context_streebog_lps( K, B );   /* новый ключ */
       }
       /* изменяем значение переменной h */
       for ( idx = 0; idx < 8; idx++ ) ctx->h[idx] ^= T[idx] ^ K[idx] ^ m[idx];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование Add (увеличение счетчика длины обработаного сообщения).                  */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_add( ak_streebog ctx, ak_uint64 size )
{
 #ifdef LIBAKRYPT_LITTLE_ENDIAN
   ak_uint64 tmp = size + ctx->n[0];
   if( tmp < ctx->n[0] ) ctx->n[1]++;
   ctx->n[0] = tmp;  /* такой код позволяет обработать сообщения, длиной не более 2^125 байт */
 #else
     ak_uint64 val = bswap_64( ctx->n[0] ),
               tmp = size + val;
     if( tmp < val ) {
       val = bswap_64( ctx->n[1] );
       val++;
       ctx->n[1] = bswap_64( val );
     }
     ctx->n[0] = bswap_64(tmp);
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование SAdd (Прибавление к массиву S вектора по модулю \f$ 2^{512} \f$).        */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_hash_context_streebog_sadd( ak_streebog ctx,  const ak_uint64 *data )
{
   int i = 0;
   ak_uint64 carry = 0;
   for( i = 0; i < 8; i++ )
   {
    #ifdef LIBAKRYPT_LITTLE_ENDIAN
      if( carry ) {
                    ctx->sigma[i] ++;
                    if( ctx->sigma[i] ) carry = 0;
      }
      ctx->sigma[i] += data[i];
      if( ctx->sigma[i] < data[i] ) carry = 1;
    #else
      ak_uint64 val_data = bswap_64( data[i] ),
               val_sigma = bswap_64( ctx->sigma[i] );
      if( carry ) {
                    val_sigma++;
                    if( val_sigma ) carry = 0;
      }
      val_sigma += val_data;
      if( val_sigma < val_data ) carry = 1;
      ctx->sigma[i] = bswap_64( val_sigma );
    #endif
   }
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_clean_streebog( ak_pointer sctx )
{
  ak_streebog cx = ( ak_streebog ) sctx;
  if( cx == NULL ) return ak_error_null_pointer;

  memset( cx->n, 0, 64 );
  memset( cx->sigma, 0, 64 );
  if( cx->hsize == 32 ) memset( cx->h, 1, 64 );
    else memset( cx->h, 0, 64 );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_update_streebog( ak_pointer sctx, const ak_pointer in, const size_t size )
{
  ak_streebog cx = ( ak_streebog ) sctx;
  ak_uint64 quot = size >> 6, *dt = ( ak_uint64 *) in;

  if( cx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to internal streebog context" );
  if(( !size ) || ( in == NULL )) return ak_error_ok;
  if(( size - ( quot << 6 )) != 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                      "data length is not a multiple of the length of the block" );
  do{
      ak_hash_context_streebog_g( cx, cx->n, dt );
      ak_hash_context_streebog_add( cx, 512 );
      ak_hash_context_streebog_sadd( cx, dt );
      quot--; dt += 8;
  } while( quot > 0 );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_finalize_streebog( ak_pointer sctx,
                   const ak_pointer in, const size_t size, ak_pointer out, const size_t out_size )
{
  ak_uint64 m[8];
  int result = ak_error_ok;
  ak_uint8 *mhide = NULL;
  ak_streebog cx = ( ak_streebog )sctx;
  struct streebog sx; /* структура для хранения копии текущего состояния контекста */

  if( cx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to internal streebog context" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to externl result buffer" );
  if( size >= 64 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                                      "input length is too huge" );
  if( out_size > cx->hsize ) return ak_error_message( ak_error_wrong_length, __func__,
                                                                 "requesting length is too huge" );
  /* формируем временный текст */
  memset( m, 0, 64 );
  if( in != NULL )
    memcpy( m, in, ( ak_uint32 )size ); /* здесь приведение типов корректно, поскольку 0 <= size < 64 */
  mhide = ( ak_uint8 * )m;
  mhide[size] = 1; /* дополнение */

  /* при финализации мы изменяем копию существующей структуры */
  memcpy( &sx, cx, sizeof( struct streebog ));
  ak_hash_context_streebog_g( &sx, sx.n, m );
  ak_hash_context_streebog_add( &sx, size << 3 );
  ak_hash_context_streebog_sadd( &sx, m );
  ak_hash_context_streebog_g( &sx, NULL, sx.n );
  ak_hash_context_streebog_g( &sx, NULL, sx.sigma );

 /* копируем нужную часть результирующего массива или выдаем сообщение об ошибке */
    if( cx->hsize == 64 ) memcpy( out, sx.h, ak_min( 64, out_size ));
      else memcpy( out, sx.h+4, ak_min( 32, out_size ));
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                               Реализация функция класса hash                                    */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    ГОСТ Р 34.11-2012, с длиной хешкода, равной 256 бит (функция Стрибог256).

    @param hctx Контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_create_streebog256( ak_hash hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
  hctx->data.sctx.hsize = 32;
  if(( hctx->oid = ak_oid_context_find_by_name( "streebog256" )) == NULL )
    return ak_error_message( ak_error_wrong_oid, __func__,
                                           "incorrect internal search of streebog256 identifier" );
  if(( error = ak_mac_context_create( &hctx->mctx, 64, &hctx->data.sctx,
                                             ak_hash_context_clean_streebog,
                                             ak_hash_context_update_streebog,
                                             ak_hash_context_finalize_streebog )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect initialization of internal mac context" );

  return ak_hash_context_clean_streebog( &hctx->data.sctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    ГОСТ Р 34.11-2012, с длиной хэшкода, равной 512 бит (функция Стрибог512).

    @param hctx Контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_create_streebog512( ak_hash hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
  hctx->data.sctx.hsize = 64;
  if(( hctx->oid = ak_oid_context_find_by_name( "streebog512" )) == NULL )
    return ak_error_message( ak_error_wrong_oid, __func__,
                                           "incorrect internal search of streebog256 identifier" );
  if(( error = ak_mac_context_create( &hctx->mctx, 64, &hctx->data.sctx,
                                             ak_hash_context_clean_streebog,
                                             ak_hash_context_update_streebog,
                                             ak_hash_context_finalize_streebog )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect initialization of internal mac context" );

  return ak_hash_context_clean_streebog( &hctx->data.sctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! В случае инициализации контекста алгоритма ГОСТ Р 34.11-94 (в настоящее время выведен из
    действия) используются фиксированные таблицы замен, определяемые константой
    `id-gosthash94-rfc4357-paramsetA`. Для создания контекста функции хеширования ГОСТ Р 34.11-94
    с другими таблицами замен нужно пользоваться функцией ak_hash_create_gosthash94().

    @param hctx Контекст функции хеширования
    @param oid OID алгоритма бесключевого хеширования.

    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_create_oid( ak_hash hctx, ak_oid oid )
{
  int error = ak_error_ok;

 /* выполняем проверку */
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to hash function OID" );
 /* проверяем, что OID от бесключевой функции хеширования */
  if( oid->engine != hash_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );
 /* проверяем, что производящая функция определена */
  if( oid->func.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                                          "using oid with undefined constructor" );
 /* инициализируем контекст */
  if(( error = (( ak_function_hash_context_create *)oid->func.create )( hctx )) != ak_error_ok )
      return ak_error_message( error, __func__, "invalid creation of hash function context");

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает значения полей структуры struct hash.

  @param hctx Контекст функции хеширования
  @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
  возвращается ее код.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_destroy( ak_hash hctx )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "destroying null pointer to hash context" );
  hctx->oid = NULL;
  memset( &hctx->data.sctx, 0, sizeof( struct streebog ));
  if( ak_mac_context_destroy( &hctx->mctx ) != ak_error_ok )
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect cleaning of internal mac context" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hash_context_delete( ak_pointer hctx )
{
  if( hctx != NULL ) {
      ak_hash_context_destroy(( ak_hash ) hctx );
      free( hctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to hash context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст функции хеширования
    @return Функция возвращает длину хеш-кода в октетах. В случае возникновения ошибки,
    возвращается ноль. Код ошики может быть получен с помощью вызова функции ak_error_get_value(). */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hash_context_get_tag_size( ak_hash hctx )
{
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to hash context" );
    return 0;
  }

 return hctx->data.sctx.hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hash.c  */
/* ----------------------------------------------------------------------------------------------- */
