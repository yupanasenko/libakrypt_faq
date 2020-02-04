/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_sign.h                                                                                 */
/*  - содержит реализацию функций для работы с электронной подписью.                               */
/* ----------------------------------------------------------------------------------------------- */
#include <ak_sign.h>
#include <ak_parameters.h>
#include <ak_context_manager.h>

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
/*! \brief Установление или изменение маски секретного ключа ассиметричного криптографического
    алгоритма.

    При первичной установке маски
    функция вырабатывает случайный вычет \f$ m \f$ из кольца вычетов \f$ \mathbb Z_q\f$
    и заменяет значение ключа \f$ k \f$ на величину \f$ km^{-1} \pmod{q} \f$.

    При смене маски
    функция вырабатывает случайный вычет \f$ \zeta \f$ из кольца вычетов \f$ \mathbb Z_q\f$
    и заменяет значение ключа \f$ k \f$ и значение маски \f$ m \f$  на значения
    \f$ k \equiv k\zeta \pmod{q} \f$ и \f$  m \equiv m\zeta^{-1} \pmod{q} \f$.

    Величина \f$ q \f$ должна быть простым числом, помещенным в параметры эллиптической кривой,
    на которые указывает `skey->data`.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_signkey_context_set_mask_multiplicative( ak_skey skey )
{
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
  ak_mpznmax u, zeta;
  ak_wcurve wc = NULL;
  int error = ak_error_ok;
  ak_uint64 *key = NULL, *mask = NULL;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
  if(( wc = ( ak_wcurve ) skey->data ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "using internal null pointer to elliptic curve" );
  key = ( ak_uint64 *)skey->key;
  mask = ( ak_uint64 *)( skey->key + skey->key_size );

 /* проверяем, установлена ли маска ранее */
  if((( skey->flags)&ak_key_flag_set_mask ) == 0 ) {
    /* создаем маску */
     if(( error = ak_random_context_random( &skey->generator,
                                                          mask, skey->key_size )) != ak_error_ok )
       return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

    /* накладываем маску на ключ
      - для этого мы вычисляем значение маски M^{-1} mod(q), хранящееся в skey->mask,
        и присваиваем ключу K значение KM mod(q)
      - при этом значения ключа и маски хранятся в представлении Монтгомери    */

#ifndef LIBAKRYPT_LITTLE_ENDIAN
     for( i = 0; i < wc->size; i++ ) key[i] = bswap_64( key[i] );
#endif

    /* приводим случайное число по модулю q и сразу считаем, что это число в представлении Монтгомери */
     ak_mpzn_rem( mask, mask, wc->q, wc->size );

    /* приводим значение ключа по модулю q, а потом переводим в представление Монтгомери
       при этом мы предполагаем, что значение ключа установлено в естественном представлении */
     ak_mpzn_rem( key, key, wc->q, wc->size );
     ak_mpzn_mul_montgomery( key, key, wc->r2q, wc->q, wc->nq, wc->size);
     ak_mpzn_mul_montgomery( key, key, mask, wc->q, wc->nq, wc->size);

    /* вычисляем обратное значение для маски */
     ak_mpzn_set_ui( u, wc->size, 2 );
     ak_mpzn_sub( u, wc->q, u, wc->size );
     ak_mpzn_modpow_montgomery( mask, // m <- m^{q-2} (mod q)
                                    mask, u, wc->q, wc->nq, wc->size );
    /* меняем значение флага */
     skey->flags |= ak_key_flag_set_mask;

  } else { /* если маска уже установлена, то мы сменяем ее на новую */

    /* создаем маску */
     if(( error = ak_random_context_random( &skey->generator, zeta,
                                               (ssize_t)skey->key_size )) != ak_error_ok )
       return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

    /* приводим случайное число по модулю q и сразу считаем, что это число в представлении Монтгомери */
     ak_mpzn_rem( zeta, zeta, wc->q, wc->size );

    /* домножаем ключ на случайное число */
     ak_mpzn_mul_montgomery( key, key, zeta, wc->q, wc->nq, wc->size );
    /* вычисляем обратное значение zeta */
     ak_mpzn_set_ui( u, wc->size, 2 );
     ak_mpzn_sub( u, wc->q, u, wc->size );
     ak_mpzn_modpow_montgomery( zeta, zeta, u, wc->q, wc->nq, wc->size ); // z <- z^{q-2} (mod q)

    /* домножаем маску на обратное значение zeta */
     ak_mpzn_mul_montgomery( mask, mask, zeta, wc->q, wc->nq, wc->size );
    }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Снятие маски секретного ключа ассиметричного криптографического алгоритма.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_signkey_context_unmask_multiplicative( ak_skey skey )
{
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
  ak_mpznmax u = ak_mpznmax_one;
  ak_wcurve wc = NULL;
  ak_uint64 *key = NULL, *mask = NULL;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
  if(( wc = ( ak_wcurve ) skey->data ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "using internal null pointer to elliptic curve" );
 /* проверяем, установлена ли маска ранее */
  if( (( skey->flags)&ak_key_flag_set_mask ) == 0 ) return ak_error_ok;

  key = ( ak_uint64 *)skey->key;
  mask = ( ak_uint64 *)( skey->key + skey->key_size );

 /* снимаем маску с ключа */
  ak_mpzn_mul_montgomery( key, key, mask, wc->q, wc->nq, wc->size );
 /* приводим ключ из представления Монтгомери в естественное состояние */
  ak_mpzn_mul_montgomery( key, key, u, wc->q, wc->nq, wc->size );
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < wc->size; i++ ) key[i] = bswap_64( key[i] );
#endif
 /* меняем значение флага */
  skey->flags ^= ak_key_flag_set_mask;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @todo Необходимо реализовать выработку контрольной суммы для секретного ключа ЭП. */
 static int ak_signkey_context_set_icode_multiplicative( ak_skey skey )
{
 (void) skey;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @todo Необходимо реализовать проверку контрольной суммы для секретного ключа ЭП. */
 static bool_t ak_signkey_context_check_icode_multiplicative( ak_skey skey )
{
 (void) skey;
 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*                    функции для работы с секретными ключами электронной подписи                  */
/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx Контекст секретного ключа электронной подписи (асимметричного алгоритма).
    @param wc Контекст параметров эллиптической кривой. Контекст однозначно связывает
    секретный ключ с эллиптической кривой, на которой происходят вычисления.

    @return Функция возвращает ноль (\ref ak_error_ok) в случае успешной иниициализации контекста.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_create_streebog256( ak_signkey sctx, const ak_wcurve wc )
{
 int error = ak_error_ok;

   if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
   if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using null pointer to elliptic curve context" );
   if( wc->size != ak_mpzn256_size ) return ak_error_message( ak_error_curve_not_supported,
                                    __func__ , "elliptic curve not supported for this algorithm" );
  /* первичная инициализация */
   memset( sctx, 0, sizeof( struct signkey ));

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_context_create_streebog256( &sctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа для хэш-кода размером 32 октета */
   if(( error = ak_skey_context_create( &sctx->key, 32 )) != ak_error_ok ) {
     ak_hash_context_destroy( &sctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* устанавливаем OID алгоритма */
   if(( sctx->key.oid = ak_oid_context_find_by_name( "sign256" )) == NULL ) {
     ak_error_message( error = ak_error_get_value(), __func__ ,
                                                     "incorrect initialization of algorithm " );
     ak_skey_context_destroy( &sctx->key );
     ak_hash_context_destroy( &sctx->ctx );
     return error;
   }

  /* устанавливаем эллиптическую кривую */
   sctx->key.data = wc;

  /* При удалении ключа не нужно освобождать память из под параметров эллиптической кривой  */
   sctx->key.flags |= ak_key_flag_data_not_free;

 /* в заключение определяем указатели на методы */
  sctx->key.set_mask = ak_signkey_context_set_mask_multiplicative;
  sctx->key.unmask = ak_signkey_context_unmask_multiplicative;
  sctx->key.set_icode = ak_signkey_context_set_icode_multiplicative;
  sctx->key.check_icode = ak_signkey_context_check_icode_multiplicative;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx Контекст секретного ключа электронной подписи (асимметричного алгоритма).
    @param wc Контекст параметров эллиптической кривой. Контекст однозначно связывает
    секретный ключ с эллиптической кривой, на которой происходят вычисления.

    @return Функция возвращает ноль (\ref ak_error_ok) в случае успешной иниициализации контекста.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_create_streebog512( ak_signkey sctx, const ak_wcurve wc )
{
 int error = ak_error_ok;

   if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
   if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using null pointer to elliptic curve context" );
   if( wc->size != ak_mpzn512_size ) return ak_error_message( ak_error_curve_not_supported,
                                    __func__ , "elliptic curve not supported for this algorithm" );
  /* первичная инициализация */
   memset( sctx, 0, sizeof( struct signkey ));

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_context_create_streebog512( &sctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_context_create( &sctx->key, 64 )) != ak_error_ok ) {
     ak_hash_context_destroy( &sctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* устанавливаем OID алгоритма */
   if(( sctx->key.oid = ak_oid_context_find_by_name( "sign512" )) == NULL ) {
     ak_error_message( error = ak_error_get_value(), __func__ ,
                                                     "incorrect initialization of algorithm " );
     ak_skey_context_destroy( &sctx->key );
     ak_hash_context_destroy( &sctx->ctx );
     return error;
   }
  /* устанавливаем эллиптическую кривую */
   sctx->key.data = wc;

  /* При удалении ключа не нужно освобождать память из под параметров эллиптической кривой  */
   sctx->key.flags |= ak_key_flag_data_not_free;

 /* в заключение определяем указатели на методы */
  sctx->key.set_mask = ak_signkey_context_set_mask_multiplicative;
  sctx->key.unmask = ak_signkey_context_unmask_multiplicative;
  sctx->key.set_icode = ak_signkey_context_set_icode_multiplicative;
  sctx->key.check_icode = ak_signkey_context_check_icode_multiplicative;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx Контекст секретного ключа электронной подписи (асимметричного алгоритма).
    @param algoid Идентификатор алгоритма выработки электронной подписи,
    то есть `algoid->engine = sign_function`.
    @param curveoid Идентификатор эллиптической кривой, зазаддной в короткой форме Вейерштрасса,
    то есть `curveoid->engine = identifier` и `curveoid->mode = wcurve_params`.

    @return Функция возвращает ноль (\ref ak_error_ok) в случае успешной иниициализации контекста.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_create_oid( ak_signkey sctx, ak_oid algoid, ak_oid curveoid )
{
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
  if( algoid == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                   "using null pointer to digital signature oid" );
 /* проверяем, что OID от правильного алгоритма выработки */
  if( algoid->engine != sign_function ) return ak_error_message( ak_error_oid_engine, __func__ ,
                                                 "using digital signature oid with wrong engine" );
  if( algoid->mode != algorithm ) return ak_error_message( ak_error_oid_mode, __func__ ,
                                                   "using digital signature oid with wrong mode" );

  if( curveoid == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to elliptic curve oid" );
  if( curveoid->engine != identifier ) return ak_error_message( ak_error_oid_engine, __func__ ,
                                                    "using elliptic curve oid with wrong engine" );
 /* проверяем, что OID от параметров кривой в форме Вейерштрасса */
  if( curveoid->mode != wcurve_params ) return ak_error_message( ak_error_oid_mode, __func__ ,
                                                      "using elliptic curve oid with wrong mode" );

 return ((ak_function_create_signkey *)algoid->func.create)( sctx,
                                                               ( const ak_wcurve )curveoid->data );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_destroy( ak_signkey sctx )
{
  int error = ak_error_ok;
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                           "destroying a null pointer to digital signature secret key context" );
  if(( error = ak_skey_context_destroy( &sctx->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying of digital signature secret key" );
  if(( error = ak_hash_context_destroy( &sctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying hash function context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_signkey_context_delete( ak_pointer sctx )
{
  if( sctx != NULL ) {
      ak_signkey_context_destroy(( ak_signkey ) sctx );
      free( sctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                   "using null pointer to digital signature secret key context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @return Функция возвращает константное значение.                                               */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_signkey_context_get_tag_size( ak_signkey sctx )
{
  if( sctx == NULL ) { ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
    return 0;
  }
  return 2*sctx->ctx.data.sctx.hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param ptr указатель на область памяти, содержащей значение секретного ключа.
    Секретный ключ интерпретируется как последовательность байт.
    @param size размер ключа в байтах.

    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_set_key( ak_signkey sctx, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;

  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to secret key context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to constant key value" );
  if( size > sctx->key.key_size ) return ak_error_message( ak_error_wrong_length, __func__,
                                                   "using constant buffer with unexpected length");
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_context_set_key( &sctx->key, ptr, size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of key data" );

 /*
    ... в процессе присвоения ключа, он приводится по модулю и маскируется
        за это отвечает функция ak_signkey_context_set_mask_multiplicative() ...  */
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param generator контекст генератора случайных чисел.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_set_key_random( ak_signkey sctx, ak_random generator )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to secret key context" );
  if( sctx->key.key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                     "using non initialized secret key context" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using null pointer to random number generator" );
 /* присваиваем секретный ключ */
  if(( error = ak_skey_context_set_key_random( &sctx->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a secret key context" );

 /*
    ... в процессе присвоения ключа, он приводится по модулю и маскируется
        за это отвечает функция ak_signkey_context_set_mask_multiplicative() ...  */
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-sign01.c
 *  \example test-sign02.c                                                                         */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.c  */
/* ----------------------------------------------------------------------------------------------- */
