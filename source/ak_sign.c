/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_sign.h                                                                                 */
/*  - содержит реализацию функций для работы с электронной подписью.                               */
/* ----------------------------------------------------------------------------------------------- */
#include <ak_sign.h>
#include <ak_tools.h>
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
    @param curveoid Идентификатор эллиптической кривой, заданной в короткой форме Вейерштрасса,
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
/*! Функция вырабатывает электронную подпись для \f$ e \f$ - вычисленного хеш-кода подписываемого
    сообщения и заданного случайного числа \f$ k \f$. Для этого

     - вычисляется точка \f$ C = [k]P\f$, где \f$ P \f$ точка, порождающая подгруппу простого
       порядка \f$ q \f$.
     - точка приводится к аффинной форме и для `х`-координаты точки \f$ C \f$ вычисляется значение
       \f$ r \equiv x \pmod{q}\f$.
     - вычисляется вторая половинка подписи  \f$ s \f$,
       удовлетворяющая сравнению \f$ s \equiv rd + ke \pmod{q}\f$.

    После этого
    формируется электронная подпись, представляющая собой конкатенацию векторов `r` и `s`.
    При этом в результирующий буффер данные помещаются следующим образом:
    в первые 256 (512) бит (младшие разряды) помещается значение \f$ s \f$ в big-endian формате,
    в последние 256 (512) бит (страшие разряды) помещается значение \f$ r \f$ в big-endian формате.

    \b Внимание! Входные параметры функции не проверяются.

    @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param k степень кратности точки \f$ P \f$; представляет собой вычет по модулю \f$ q \f$ - порядка
           группы точек эллиптической кривой;
           при вычислении подписи предполагается, что под вычет выделена память в количестве
           `wc->size` слов размера 64 бита, где `wc` используемая эллиптическая кривая.

    @param e целое число, соотвествующее хеш-коду подписываемого сообщения,
           заранее приведить значение по модулю `q` не требуется.

    @param out массив, куда помещается результат. Память под массив должна быть выделена заранее.

    \warning Поскольку `k` и `e` являются массивами 64 битных чисел, используемая архитектура
    влияет на значение вычета. Необходимо учитывать это, если вызов функции используется
    напрямую, минуя вызов функций ak_signkey_context_sign_hash() или ak_signkey_context_sign_ptr().*/
/* ----------------------------------------------------------------------------------------------- */
 void ak_signkey_context_sign_const_values( ak_signkey sctx,
                                                       ak_uint64 *k, ak_uint64 *e, ak_pointer out )
{
  ak_mpzn512 r, s;
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;

 /* поскольку функция не экспортируется, мы оставляем все проверки функциям верхнего уровня */
 /* вычисляем r */
  ak_wpoint_pow( &wr, &wc->point, k, wc->size, wc );
  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );

 /* приводим r к виду Монтгомери и помещаем во временную переменную wr.x <- r */
  ak_mpzn_mul_montgomery( wr.x, r, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем значение s <- r*d (mod q) (сначала домножаем на ключ, потом на его маску) */
  ak_mpzn_mul_montgomery( s, wr.x, (ak_uint64 *)sctx->key.key, wc->q, wc->nq, wc->size );
  ak_mpzn_mul_montgomery( s, s,
              (ak_uint64 *)(sctx->key.key+sctx->key.key_size), wc->q, wc->nq, wc->size );

 /* приводим k к виду Монтгомери и помещаем во временную переменную wr.y <- k */
  ak_mpzn_mul_montgomery( wr.y, k, wc->r2q, wc->q, wc->nq, wc->size );

 /* приводим e к виду Монтгомери и помещаем во временную переменную wr.z <- e */
  ak_mpzn_rem( wr.z, e, wc->q, wc->size );
  if( ak_mpzn_cmp_ui( wr.z, wc->size, 0 )) ak_mpzn_set_ui( wr.z, wc->size, 1 );
  ak_mpzn_mul_montgomery( wr.z, wr.z, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем k*e (mod q) и вычисляем s = r*d + k*e (mod q) (в форме Монтгомери) */
  ak_mpzn_mul_montgomery( wr.y, wr.y, wr.z, wc->q, wc->nq, wc->size ); /* wr.y <- k*e */
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

 /* приводим s к обычной форме */
  ak_mpzn_mul_montgomery( s, s,  wc->point.z, /* для экономии памяти пользуемся равенством z = 1 */
                                 wc->q, wc->nq, wc->size );
 /* экспортируем результат */
  ak_mpzn_to_little_endian( s, wc->size, out, sizeof(ak_uint64)*wc->size, ak_true );
  ak_mpzn_to_little_endian( r, wc->size, (ak_uint64 *)out + wc->size,
                                                             sizeof(ak_uint64)*wc->size, ak_true );
 /* завершаемся */
  memset( &wr, 0, sizeof( struct wpoint ));
  sctx->key.set_mask( &sctx->key );
  memset( r, 0, sizeof( ak_mpznmax ));
  memset( s, 0, sizeof( ak_mpznmax ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx Контекст секретного ключа алгоритма электронной подписи.
    @param hash Последовательность байт, содержащая в себе хеш-код
    подписываемого сообщения.
    @param size Размер хеш-кода, в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    @param out_size Размер выделенной под выработанную ЭП памяти.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_sign_hash( ak_signkey sctx, ak_pointer hash,
                                                      size_t size, ak_pointer out, size_t out_size )
{
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
  size_t lb = 0;
  ak_mpzn512 k, h;
  int error = ak_error_ok;
 /* нужен нам для доступа к системному генератору случайных чисел */
  ak_context_manager manager = NULL;

  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( hash == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to hash value" );
  if( size != ( lb = sizeof( ak_uint64 )*(( ak_wcurve )sctx->key.data)->size ))
    return ak_error_message( ak_error_wrong_length, __func__,
                                                            "using hash value with wrong length" );
  if( out_size < 2*lb ) return ak_error_message( ak_error_wrong_length, __func__,
                                                       "using small buffer for digital sigature" );

 /* получаем доступ к генератору случайных чисел */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__,
                                                "using bull pointer to internal context manager" );
 /* вырабатываем случайное число */
  memset( k, 0, sizeof( ak_uint64 )*ak_mpzn512_size );
  if(( error = ak_mpzn_set_random_modulo( k, (( ak_wcurve )sctx->key.data)->q,
                  (( ak_wcurve )sctx->key.data)->size, &manager->key_generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "invalid generation of random value");

 /* превращаем хеш от сообщения в последовательность 64х битных слов  */
  memcpy( h, hash, sctx->ctx.data.sctx.hsize );
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < (( ak_wcurve )sctx->key.data)->size; i++ ) h[i] = bswap_64( h[i] );
#endif

 /* и только теперь вычисляем электронную подпись */
  ak_signkey_context_sign_const_values( sctx, k, h, out );
  ak_ptr_context_wipe( k, sizeof( ak_uint64 )*ak_mpzn512_size, &sctx->key.generator );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx Контекст секретного ключа алгоритма электронной подписи.
    @param in Указатель на входные данные которые подписываются.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    @param out_size Размер выделенной под выработанную ЭП памяти.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_sign_ptr( ak_signkey sctx,
                          const ak_pointer in, const size_t size, ak_pointer out, size_t out_size )
{
  int error = ak_error_ok;
  ak_uint8 hash[128]; /* выбираем максимально возможный размер */

 /* необходимые проверки */
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
  if( in == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to signifying value" );
  if( sctx->ctx.data.sctx.hsize > 64 ) return ak_error_message( ak_error_wrong_length,
                             __func__, "using hash function with very large hash code size" );

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, sizeof( hash ));
  if(( error = ak_hash_context_ptr( &sctx->ctx, in, size,
                                                      hash, sizeof( hash ))) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong calculation of hash value" );

 /* выработанный хеш-код представляет собой последовательность байт
    данная последовательность не зависит от используемой архитектуры используемой ЭВМ */
 return ak_signkey_context_sign_hash( sctx, hash, sctx->ctx.data.sctx.hsize, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param filename Строка с именем файла для которого вычисляется электронная подпись.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    @param out_size Размер выделенной под выработанную ЭП памяти.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_sign_file( ak_signkey sctx, const char *filename,
                                                                   ak_pointer out, size_t out_size )
{
  int error = ak_error_ok;
  ak_uint8 hash[128]; /* выбираем максимально возможный размер */

 /* необходимые проверки */
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to file name" );
  if( sctx->ctx.data.sctx.hsize > 64 ) return ak_error_message( ak_error_wrong_length,
                             __func__, "using hash function with very large hash code size" );

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, sizeof( hash ));
  if(( error = ak_hash_context_file( &sctx->ctx, filename,
                                                     hash, sizeof( hash ))) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong calculation of hash value" );

 /* выработанный хеш-код представляет собой последовательность байт
    данная последовательность не зависит от используемой архитектуры используемой ЭВМ */
 return ak_signkey_context_sign_hash( sctx, hash, sctx->ctx.data.sctx.hsize, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*                     функции для работы с открытыми ключами электронной подписи                  */
/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx Контекст открытого ключа электронной подписи
    @param wc Контекст эллиптической кривой.

    @return В случае успеха возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_context_create_streebog256( ak_verifykey pctx, const ak_wcurve wc )
{
  int error = ak_error_ok;
  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature public key context" );
  if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using null pointer to elliptic curve context" );
  if( wc->size != ak_mpzn256_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                    "using wrong elliptic curve" );
 /* очищаем контекст */
  memset( pctx, 0, sizeof( struct verifykey ));

 /* инициализируем контекст функции хеширования */
  if(( error = ak_hash_context_create_streebog256( &pctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid creation of hash function context");

 /* устанавливаем эллиптическую кривую */
  pctx->wc = wc;

 /* устанавливаем oid алгоритма */
  if(( pctx->oid = ak_oid_context_find_by_name( "verify256" )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ ,
                                                "incorrect initialization of hash function OID" );
  pctx->flags = ak_key_flag_undefined;
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx Контекст открытого ключа электронной подписи
    @param wc Контекст эллиптической кривой.

    @return В случае успеха возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_context_create_streebog512( ak_verifykey pctx, const ak_wcurve wc )
{
  int error = ak_error_ok;
  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature public key context" );
  if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using null pointer to elliptic curve context" );
  if( wc->size != ak_mpzn512_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                    "using wrong elliptic curve" );
 /* очищаем контекст */
  memset( pctx, 0, sizeof( struct verifykey ));

 /* инициализируем контекст функции хеширования */
  if(( error = ak_hash_context_create_streebog512( &pctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid creation of hash function context");

 /* устанавливаем эллиптическую кривую */
  pctx->wc = wc;

 /* устанавливаем oid алгоритма */
  if(( pctx->oid = ak_oid_context_find_by_name( "verify512" )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ ,
                                                "incorrect initialization of hash function OID" );
  pctx->flags = ak_key_flag_undefined;
 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст открытого ключа и вычисляет его значение
    (точку эллиптической кривой), соответствующее заданному значению секретного ключа.

    @param pctx Контекст открытого ключа электронной подписи
    @param sctx Контекст секретного ключа электронной подписи. Контекст должен быть предварительно
    инициализирован и содержать в себе ключевое значение.

    @return В случае успеха возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_context_create_from_signkey( ak_verifykey pctx, ak_signkey sctx )
{
  int error = ak_error_ok;
  ak_mpzn512 k, one = ak_mpzn512_one;

  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                 "using a null pointer to digital signature secret key context" );

  if( strncmp( "sign256", sctx->key.oid->names[1], 7 ) == 0 ) {
    if(( error = ak_verifykey_context_create_streebog256( pctx,
                                                  ( ak_wcurve )sctx->key.data )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect initialization of public key context" );
  } else {
     if( strncmp( "sign512", sctx->key.oid->names[1], 7 ) == 0 ) {
       if(( error = ak_verifykey_context_create_streebog512( pctx,
                                                  ( ak_wcurve )sctx->key.data )) != ak_error_ok )
         return ak_error_message( error, __func__,
                                               "incorrect initialization of public key context" );
     } else return ak_error_message( error, __func__, "using incorrect oid for secret key" );
   }

 /* теперь определяем открытый ключ */
  ak_mpzn_mul_montgomery( k, ( ak_uint64 *)sctx->key.key, one,
                                                      pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_wpoint_pow( &pctx->qpoint, &pctx->wc->point, k, pctx->wc->size, pctx->wc );

  ak_mpzn_mul_montgomery( k, ( ak_uint64 *)( sctx->key.key + sctx->key.key_size ),
                                                  one, pctx->wc->q, pctx->wc->nq, pctx->wc->size);
  ak_wpoint_pow( &pctx->qpoint, &pctx->qpoint, k, pctx->wc->size, pctx->wc );
  ak_wpoint_reduce( &pctx->qpoint, pctx->wc );

 /* перемаскируем секретный ключ */
  pctx->flags = ak_key_flag_set_key;
  ak_ptr_context_wipe( k, sizeof( ak_uint64 )*ak_mpzn512_size, &sctx->key.generator );
  sctx->key.set_mask( &sctx->key );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа алгоритма электронной подписи.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_context_destroy( ak_verifykey pctx )
{
  int error = ak_error_ok;
  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to public key context" );
  if(( error = ak_hash_context_destroy( &pctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying hash function context" );

  memset( pctx, 0, sizeof( struct verifykey ));
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа алгоритма электронной подписи.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_verifykey_context_delete( ak_pointer pctx )
{
  if( pctx != NULL ) {
      ak_verifykey_context_destroy(( ak_verifykey ) pctx );
      free( pctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                   "using null pointer to digital signature public key context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа.
    @param hash хеш-код сообщения (последовательность байт), для которого проверяется электронная подпись.
    @param hsize размер хеш-кода, в байтах.
    @param sign электронная подпись, для которой выполняется проверка.
    @return Функция возыращает истину, если подпись верна. Если функция не верна или если
    возникла ошибка, то возвращается ложь. Код Ошибки может получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_verifykey_context_verify_hash( ak_verifykey pctx,
                                        const ak_pointer hash, const size_t hsize, ak_pointer sign )
{
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
  ak_mpzn512 v, z1, z2, u, r, s, h;
  struct wpoint cpoint, tpoint;

  if( pctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                               "using a null pointer to secret key context" );
    return ak_false;
  }
  if( hash == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hash value" );
    return ak_false;
  }
  if( hsize != sizeof( ak_uint64 )*(pctx->wc->size )) {
    ak_error_message( ak_error_wrong_length, __func__, "using hash value with wrong length" );
    return ak_false;
  }
  if( sign == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to sign value" );
    return ak_false;
  }

 /* импортируем подпись */
  ak_mpzn_set_little_endian( s, pctx->wc->size, sign, sizeof(ak_uint64)*pctx->wc->size, ak_true );
  ak_mpzn_set_little_endian( r, pctx->wc->size, ( ak_uint64* )sign + pctx->wc->size,
                                                      sizeof(ak_uint64)*pctx->wc->size, ak_true );
  memcpy( h, hash, sizeof( ak_uint64 )*pctx->wc->size );
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < pctx->wc->size; i++ ) h[i] = bswap_64( h[i] );
#endif

  ak_mpzn_set( v, h, pctx->wc->size );
  ak_mpzn_rem( v, v, pctx->wc->q, pctx->wc->size );
  if( ak_mpzn_cmp_ui( v, pctx->wc->size, 0 )) ak_mpzn_set_ui( v, pctx->wc->size, 1 );
  ak_mpzn_mul_montgomery( v, v, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

  /* вычисляем v (в представлении Монтгомери) */
  ak_mpzn_set_ui( u, pctx->wc->size, 2 );
  ak_mpzn_sub( u, pctx->wc->q, u, pctx->wc->size );
  ak_mpzn_modpow_montgomery( v, v, u, pctx->wc->q, pctx->wc->nq, pctx->wc->size ); // v <- v^{q-2} (mod q)

  /* вычисляем z1 */
  ak_mpzn_mul_montgomery( z1, s, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_mpzn_mul_montgomery( z1, z1, v, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_mpzn_mul_montgomery( z1, z1, pctx->wc->point.z, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

  /* вычисляем z2 */
  ak_mpzn_mul_montgomery( z2, r, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_mpzn_sub( z2, pctx->wc->q, z2, pctx->wc->size );
  ak_mpzn_mul_montgomery( z2, z2, v, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_mpzn_mul_montgomery( z2, z2, pctx->wc->point.z, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

 /* сложение точек и проверка */
  ak_wpoint_pow( &cpoint, &pctx->wc->point, z1, pctx->wc->size, pctx->wc );
  ak_wpoint_pow( &tpoint, &pctx->qpoint, z2, pctx->wc->size, pctx->wc );
  ak_wpoint_add( &cpoint, &tpoint, pctx->wc );
  ak_wpoint_reduce( &cpoint, pctx->wc );
  ak_mpzn_rem( cpoint.x, cpoint.x, pctx->wc->q, pctx->wc->size );

  if( ak_mpzn_cmp( cpoint.x, r, pctx->wc->size )) {
    ak_ptr_is_equal_with_log( cpoint.x, r, pctx->wc->size*sizeof( ak_uint64 ));
    return ak_false;
  }
 return ak_true;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                    функции тестирования                                         */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_signkey_test( void )
{
 /* секретные ключи определяются последовательностями байт */
 /* d = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"; */
  ak_uint8 key256[32] = {
   0x28, 0x3B, 0xEC, 0x91, 0x98, 0xCE, 0x19, 0x1D, 0xEE, 0x7E, 0x39, 0x49, 0x1F, 0x96, 0x60, 0x1B,
   0xC1, 0x72, 0x9A, 0xD3, 0x9D, 0x35, 0xED, 0x10, 0xBE, 0xB9, 0x9B, 0x78, 0xDE, 0x9A, 0x92, 0x7A };

 /* определяем значение открытого ключа
     Q.x = 7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b
     Q.y = 26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da
     Q.z = 0000000000000000000000000000000000000000000000000000000000000001 */
  ak_mpzn256 pkey256x =
    { 0x6689dbd8e56fd80b, 0x8585ba1d4e9b788f, 0xd8595bec458b50c5, 0x7f2b49e270db6d90 };
  ak_mpzn256 pkey256y =
    { 0xdffb101a87ff77da, 0xaf64d1c593d26627, 0x85c8413a977b3cbb, 0x26f1b489d6701dd1 };
  ak_mpzn256 pkey256z = { 0x01, 0x0, 0x0, 0x0 };

 /* d = BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4 */
  ak_uint8 key512[64] = {
   0xd4, 0x8d, 0xa1, 0x1f, 0x82, 0x67, 0x29, 0xc6, 0xdf, 0xaa, 0x18, 0xfd, 0x7b, 0x6b, 0x63, 0xa2,
   0x14, 0x27, 0x7e, 0x82, 0xd2, 0xda, 0x22, 0x33, 0x56, 0xa0, 0x00, 0x22, 0x3b, 0x12, 0xe8, 0x72,
   0x20, 0x10, 0x8b, 0x50, 0x8e, 0x50, 0xe7, 0x0e, 0x70, 0x69, 0x46, 0x51, 0xe8, 0xa0, 0x91, 0x30,
   0xc9, 0xd7, 0x56, 0x77, 0xd4, 0x36, 0x09, 0xa4, 0x1b, 0x24, 0xae, 0xad, 0x8a, 0x04, 0xa6, 0x0b };

 /* е = 2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5 */
  ak_uint64 e256[ak_mpzn256_size]  =
    { 0x67ECE6672B043EE5LL, 0xCE52032AB1022E8ELL, 0x88C09C52E0EEC61FLL, 0x2DFBC1B372D89A11LL };

 /* k = 77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3 */
  ak_uint64 k256[ak_mpzn256_size]  =
    { 0x4FED924594DCEAB3LL, 0x6DE33814E95B7FE6LL, 0x2823C8CF6FCC7B95LL, 0x77105C9B20BCD312LL };

 /* результирующие последовательности - электронные подписи, также представляются последовательностями байт */
  ak_uint8 sign256[64] =
    { 0x01, 0x45, 0x6c, 0x64, 0xba, 0x46, 0x42, 0xa1, 0x65, 0x3c, 0x23, 0x5a, 0x98, 0xa6, 0x02, 0x49,
      0xbc, 0xd6, 0xd3, 0xf7, 0x46, 0xb6, 0x31, 0xdf, 0x92, 0x80, 0x14, 0xf6, 0xc5, 0xbf, 0x9c, 0x40,
      0x41, 0xaa, 0x28, 0xd2, 0xf1, 0xab, 0x14, 0x82, 0x80, 0xcd, 0x9e, 0xd5, 0x6f, 0xed, 0xa4, 0x19,
      0x74, 0x05, 0x35, 0x54, 0xa4, 0x27, 0x67, 0xb8, 0x3a, 0xd0, 0x43, 0xfd, 0x39, 0xdc, 0x04, 0x93 };

  ak_uint64 e[64];
  char *str = NULL;
  struct signkey sk;
  ak_uint8 sign[128];
  struct verifykey pk;
  int error = ak_error_ok, audit = ak_log_get_level();

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing digital signatures started" );

 /* 1. первый пример из приложения А ГОСТ Р 34.10-2012. */
  if(( error = ak_signkey_context_create_streebog256( &sk,
    (ak_wcurve) &id_tc26_gost_3410_2012_256_paramSetTest )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,
             "incorrect creation of 256 bits secret key for GOST R 34.10-2012" );
    return ak_false;
  }

  if(( error = ak_signkey_context_set_key( &sk, key256, sizeof( key256 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a constant key value" );
    ak_signkey_context_destroy( &sk );
    return ak_false;
  }

  memset( sign, 0, 64 );
  ak_signkey_context_sign_const_values( &sk, k256, (ak_uint64 *)e256, sign );
  if( ak_ptr_is_equal_with_log( sign, ( ak_pointer )sign256, 64 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
         "digital signature generation process from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
     ak_error_message( ak_error_not_equal_data, __func__ ,
      "digital signature generation process from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
     ak_signkey_context_destroy( &sk );
     return ak_false;
   }

  if(( error = ak_verifykey_context_create_from_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_context_destroy( &sk );
    return ak_false;
  }
  ak_signkey_context_destroy( &sk );

 /* проверяем открытый ключ */
  if( ak_mpzn_cmp( pk.qpoint.x, pkey256x, pk.wc->size )) {
     ak_ptr_is_equal_with_log( pk.qpoint.x, pkey256x, pk.wc->size*sizeof( ak_uint64 ));
     ak_error_message( ak_error_not_equal_data, __func__ , "public key x-coordinate is wrong" );
     ak_verifykey_context_destroy( &pk );
     return ak_false;
   }
  if( ak_mpzn_cmp( pk.qpoint.y, pkey256y, pk.wc->size )) {
     ak_ptr_is_equal_with_log( pk.qpoint.y, pkey256y, pk.wc->size*sizeof( ak_uint64 ));
     ak_error_message( ak_error_not_equal_data, __func__ , "public key y-coordinate is wrong" );
     ak_verifykey_context_destroy( &pk );
     return ak_false;
   }
  if( ak_mpzn_cmp( pk.qpoint.z, pkey256z, pk.wc->size )) {
     ak_error_message( ak_error_not_equal_data, __func__ , "public key y-coordinate is wrong" );
     ak_verifykey_context_destroy( &pk );
     return ak_false;
   }

  if( ak_verifykey_context_verify_hash( &pk, e256, 32, sign )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification process from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification process from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_verifykey_context_destroy( &pk );
      return ak_false;
  }

  ak_verifykey_context_destroy( &pk );

 /*
     ...
           */

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_get_value(), __func__ ,
                                                "testing digital signatures ended successfully" );
 return ak_true;
}
/* ----------------------------------------------------------------------------------------------- */
/*! \example test-sign01.c
 *  \example test-sign02.c                                                                         */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.c  */
/* ----------------------------------------------------------------------------------------------- */
