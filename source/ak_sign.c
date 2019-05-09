/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_sign.h                                                                                 */
/*  - содержит реализацию функций для работы с электронной подписью.                               */
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
 #include <ak_sign.h>
 #include <ak_parameters.h>
 #include <ak_context_manager.h>

 #include <stdio.h>

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

 /* выполняем стандартные проверки */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

  if(( wc = ( ak_wcurve ) skey->data ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                      "using internal null pointer to elliptic curve" );

 /* проверяем, установлена ли маска ранее */
  if( (( skey->flags)&skey_flag_set_mask ) == 0 ) {
    /* создаем маску*/
     if(( error = ak_random_context_random( &skey->generator,
                           skey->mask.data, (ssize_t)skey->mask.size )) != ak_error_ok )
     return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

    /* накладываем маску на ключ
      - для этого мы вычисляем значение маски M^{-1} mod(q), хранящееся в skey->mask,
        и присваиваем ключу K значение KM mod(q)
      - при этом значения ключа и маски хранятся в представлении Монтгомери    */

#ifndef LIBAKRYPT_LITTLE_ENDIAN
     for( i = 0; i < wc->size; i++ ) ((ak_uint64* )skey->key.data)[i] = bswap_64( ((ak_uint64* )skey->key.data)[i] );
#endif

    /* приводим случайное число по модулю q и сразу считаем, что это число в представлении Монтгомери */
     ak_mpzn_rem( (ak_uint64 *)skey->mask.data, (ak_uint64 *)skey->mask.data, wc->q, wc->size );

    /* приводим значение ключа по модулю q, а потом переводим в представление Монтгомери
       при этом мы предполагаем, что значение ключа установлено в естественном представлении */
     ak_mpzn_rem( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data, wc->q, wc->size );
     ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data, wc->r2q,
                                                                           wc->q, wc->nq, wc->size);
     ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data,
                (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->mask.data, wc->q, wc->nq, wc->size);

    /* вычисляем обратное значение для маски */
     ak_mpzn_set_ui( u, wc->size, 2 );
     ak_mpzn_sub( u, wc->q, u, wc->size );
     ak_mpzn_modpow_montgomery( (ak_uint64 *)skey->mask.data, // m <- m^{q-2} (mod q)
                                         (ak_uint64 *)skey->mask.data, u, wc->q, wc->nq, wc->size );
    /* меняем значение флага */
     skey->flags |= skey_flag_set_mask;

  } else { /* если маска уже установлена, то мы ее сменяем */

    /* создаем маску */
     if(( error = ak_random_context_random( &skey->generator, zeta,
                                              (ssize_t)skey->mask.size )) != ak_error_ok )
       return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

    /* приводим случайное число по модулю q и сразу считаем, что это число в представлении Монтгомери */
     ak_mpzn_rem( zeta, zeta, wc->q, wc->size );

    /* домножаем ключ на случайное число */
     ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data,
                                                                    zeta, wc->q, wc->nq, wc->size );
    /* вычисляем обратное значение zeta */
     ak_mpzn_set_ui( u, wc->size, 2 );
     ak_mpzn_sub( u, wc->q, u, wc->size );
     ak_mpzn_modpow_montgomery( zeta, zeta, u, wc->q, wc->nq, wc->size ); // z <- z^{q-2} (mod q)

    /* домножаем маску на обратное значение zeta */
     ak_mpzn_mul_montgomery( (ak_uint64 *)skey->mask.data, (ak_uint64 *)skey->mask.data,
                                                                   zeta, wc->q, wc->nq, wc->size );
  }
 return error;
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
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

  if(( wc = ( ak_wcurve ) skey->data ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                      "using internal null pointer to elliptic curve" );
 /* проверяем, установлена ли маска ранее */
  if( (( skey->flags)&skey_flag_set_mask ) == 0 ) return ak_error_ok;

 /* снимаем маску с ключа */
  ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data,
                                        (ak_uint64 *)skey->mask.data, wc->q, wc->nq, wc->size );
 /* приводим ключ из представления Монтгомери в естественное состояние */
  ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data,
                                                                   u, wc->q, wc->nq, wc->size );
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < wc->size; i++ ) ((ak_uint64* )skey->key.data)[i] = bswap_64( ((ak_uint64* )skey->key.data)[i] );
#endif
 /* меняем значение флага */
  skey->flags ^= skey_flag_set_mask;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @todo Необходимо реализовать выработку контрольной суммы для секретного ключа ЭП. */
 static int ak_signkey_context_set_icode_multiplicative( ak_skey skey )
{
 (void)skey;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @todo Необходимо реализовать проверку контрольной суммы для секретного ключа ЭП. */
 static bool_t ak_signkey_context_check_icode_multiplicative( ak_skey skey )
{
 (void)skey;
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

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_context_create( &sctx->key, sctx->ctx.hsize, 8 )) != ak_error_ok ) {
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
   sctx->key.flags |= skey_flag_data_not_free;

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
   if(( error = ak_skey_context_create( &sctx->key, sctx->ctx.hsize, 8 )) != ak_error_ok ) {
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
   sctx->key.flags |= skey_flag_data_not_free;

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
 size_t ak_signkey_context_get_code_size( ak_signkey sctx )
{
  if( sctx == NULL ) { ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
    return 0;
  }
  return 2*sctx->ctx.hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param ptr указатель на область памяти, содержащей значение секретного ключа.
    Секретный ключ интерпретируется как последовательность байт.

    @param size размер ключа в байтах.
    @param cflag Флаг передачи владения указателем `ptr`. Если `cflag` ложен (принимает значение `ak_false`),
    то физического копирования данных не происходит: внутренний буфер лишь указывает на размещенные
    в другом месте данные, но не владеет ими. Если `cflag` истиннен (принимает значение `ak_true`),
    то происходит выделение памяти и копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_set_key( ak_signkey sctx, const ak_pointer ptr,
                                                            const size_t size, const bool_t cflag )
{
  int error = ak_error_ok;

  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to secret key context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to constant key value" );
  if( size > sctx->key.key.size ) return ak_error_message( ak_error_wrong_length, __func__,
                                                   "using constant buffer with unexpected length");
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_context_set_key( &sctx->key, ptr, size, cflag )) != ak_error_ok )
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
  if( sctx->key.key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
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
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;
  ak_uint64 *r = (ak_uint64 *)out, *s = ( ak_uint64 *)out + wc->size;

 /* поскольку функция не экспортируется, мы оставляем все проверки функциям верхнего уровня */
 /* вычисляем r */
  ak_wpoint_pow( &wr, &wc->point, k, wc->size, wc );
  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );

 /* приводим r к виду Монтгомери и помещаем во временную переменную wr.x <- r */
  ak_mpzn_mul_montgomery( wr.x, r, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем значение s <- r*d (mod q) (сначала домножаем на ключ, потом на его маску) */
  ak_mpzn_mul_montgomery( s, wr.x, sctx->key.key.data, wc->q, wc->nq, wc->size );
  ak_mpzn_mul_montgomery( s, s, sctx->key.mask.data, wc->q, wc->nq, wc->size );

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
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < 2*wc->size; i++ ) ((ak_uint64* )out)[i] = bswap_64( ((ak_uint64* )out)[i] );
#endif

 /* завершаемся */
  memset( &wr, 0, sizeof( struct wpoint ));
  sctx->key.set_mask( &sctx->key );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param hash последовательность байт, содержащая в себе хеш-код
    подписываемого сообщения.
    @param size размер хеш-кода, в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_signkey_context_sign_hash( ak_signkey sctx,
                                                      ak_pointer hash, size_t size, ak_pointer out )
{
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
  ak_mpzn512 k, h;
  ak_pointer pout = out;
  ak_buffer result = NULL;
  int error = ak_error_ok;
 /* нужен нам для доступа к системному генератору случайных чисел */
  ak_context_manager manager = NULL;

  if( sctx == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return NULL;
  }
  if( hash == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to hash value" );
    return NULL;
  }
  if( size != sizeof( ak_uint64 )*(( ak_wcurve )sctx->key.data)->size ) {
    ak_error_message( ak_error_wrong_length, __func__, "using hash value with wrong length" );
    return NULL;
  }

 /* получаем доступ к генератору случайных чисел */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                "using internal pointer to context manager" );
    return NULL;
  }

 /* вырабатываем случайное число */
  memset( k, 0, sizeof( ak_uint64 )*ak_mpzn512_size );
  if(( error = ak_mpzn_set_random_modulo( k, (( ak_wcurve )sctx->key.data)->q,
  (( ak_wcurve )sctx->key.data)->size, &manager->key_generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid generation of random value");
    return NULL;
  }

 /* определяем указатель на область памяти, в которую будет помещен результат вычислений */
  if( pout == NULL ) {
    if(( result = ak_buffer_new_size( 2*size )) != NULL )
      pout = result->data;
     else {
      ak_error_message( ak_error_get_value( ), __func__ , "wrong creation of result buffer" );
      goto lab_exit;
     }
  }

 /* превращаем хеш от сообщения в последовательность 64х битных слов  */
  memcpy( h, hash, sctx->ctx.hsize );
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < (( ak_wcurve )sctx->key.data)->size; i++ ) h[i] = bswap_64( h[i] );
#endif

 /* и только теперь вычисляем электронную подпись */
  ak_signkey_context_sign_const_values( sctx, k, h, pout );

 lab_exit:
   ak_ptr_wipe( k, sizeof( ak_uint64 )*ak_mpzn512_size, &sctx->key.generator, ak_true );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param in Указатель на входные данные которые подписываются.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_signkey_context_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_signkey_context_sign_ptr( ak_signkey sctx,
                                           const ak_pointer in, const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  ak_uint8 hash[64]; /* выбираем максимально возможный размер */

 /* необходимые проверки */
  if( sctx == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return NULL;
  }
  if( in == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to signifying value" );
    return NULL;
  }
  if( sctx->ctx.hsize > 64 ) { ak_error_message( ak_error_wrong_length, __func__,
                                       "using hash function with very large hash code size" );
    return NULL;
  }

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, 64 );
  ak_hash_context_ptr( &sctx->ctx, in, size, hash );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return NULL;
  }

 /* выработанный хеш-код представляет собой последовательность байт
    данная последовательность не зависит от используемой архитектуры используемой ЭВМ */
 return ak_signkey_context_sign_hash( sctx, hash, sctx->ctx.hsize, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param filename Строка с именем файла для которого вычисляется электронная подпись.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_signkey_context_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_signkey_context_sign_file( ak_signkey sctx, const char *filename, ak_pointer out )
{
  ak_uint8 hash[64];
  int error = ak_error_ok;

 /* необходимые проверки */
  if( sctx == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return NULL;
  }
  if( filename == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to file name" );
    return NULL;
  }
  if( sctx->ctx.hsize > 64 ) { ak_error_message( ak_error_wrong_length, __func__,
                                            "using hash function with large hash code size" );
    return NULL;
  }

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, 64 );
  ak_hash_context_file( &sctx->ctx, filename, hash );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return NULL;
  }

 return ak_signkey_context_sign_hash( sctx, hash, sctx->ctx.hsize, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*                     функции для работы с открытыми ключами электронной подписи                  */
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

  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                            "using null pointer to digital signature public key context" );
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                          "using a null pointer to digital signature secret key context" );

 /* устанавливаем OID алгоритма */
  if( strncmp( "sign256", sctx->key.oid->name, 7 ) == 0 ) {
    if(( pctx->oid = ak_oid_context_find_by_name( "verify256" )) == NULL )
      ak_error_message( ak_error_get_value(), __func__ ,
                                             "incorrect initialization of algorithm OID" );
  }
  if( strncmp( "sign512", sctx->key.oid->name, 7 ) == 0 ) {
    if(( pctx->oid = ak_oid_context_find_by_name( "verify512" )) == NULL )
      ak_error_message( ak_error_get_value(), __func__ ,
                                             "incorrect initialization of algorithm OID" );
  }

 /* инициализируем контекст функции хеширования */
  if(( error = ak_hash_context_create_oid( &pctx->ctx, sctx->ctx.oid )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid creation of hash function context");

 /* устанавливаем эллиптическую кривую */
  pctx->wc = ( ak_wcurve )sctx->key.data;

 /* теперь определяем открытый ключ */
  ak_mpzn_mul_montgomery( k, (ak_uint64 *)sctx->key.key.data, one,
                                                      pctx->wc->q, pctx->wc->nq, pctx->wc->size);
  ak_wpoint_pow( &pctx->qpoint, &pctx->wc->point, k, pctx->wc->size, pctx->wc );
  ak_mpzn_mul_montgomery( k, (ak_uint64 *)sctx->key.mask.data, one,
                                                      pctx->wc->q, pctx->wc->nq, pctx->wc->size);
  ak_wpoint_pow( &pctx->qpoint, &pctx->qpoint, k, pctx->wc->size, pctx->wc );
  ak_wpoint_reduce( &pctx->qpoint, pctx->wc );

 /* перемаскируем секретный ключ */
  sctx->key.set_mask( &sctx->key );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст открытого ключа и присваивает ему значение,
    переданное в качестве аргументов функции. Формат передаваемых данных
    соответсвует тому, что формируется функцией ak_verify_context_export_ptr().

    @param pctx Контекст открытого ключа электронной подписи
    @param key Вектор (последовательность байт), образующая открытый ключ.
    @param size Длина открытого ключа в байтах.
    @param wc Указатель на параметры эллиптической кривой.

    @return В случае успеха возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_context_create_from_ptr( ak_verifykey pctx,
                                                  ak_pointer key, size_t size, const ak_wcurve wc )
{
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
  size_t blen = 0;
  int error = ak_error_ok;

  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                     "using null pointer to digital signature public key context" );
  if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                     "using a null pointer to digital signature secret key value" );
  if(( size != 64 ) && ( size != 128 )) return ak_error_message( ak_error_wrong_key_length,
                                                 __func__, "using a secret key with wrong length" );
  if(( wc->size != ak_mpzn256_size ) && ( wc->size != ak_mpzn512_size ))
    return ak_error_message( ak_error_wrong_length, __func__, "unexpected elliptic curve" );

 /* устанавливаем OID алгоритма */
  if( wc->size == ak_mpzn256_size ) {
    if(( pctx->oid = ak_oid_context_find_by_name( "verify256" )) == NULL )
      ak_error_message( ak_error_get_value(), __func__ ,
                                             "incorrect initialization of algorithm OID" );
    if(( error = ak_hash_context_create_streebog256( &pctx->ctx )) != ak_error_ok )
      return ak_error_message( error, __func__, "invalid creation of streebog256 context ");
  }

  if( wc->size == ak_mpzn512_size ) {
    if(( pctx->oid = ak_oid_context_find_by_name( "verify512" )) == NULL )
      ak_error_message( ak_error_get_value(), __func__ ,
                                              "incorrect initialization of algorithm OID" );
    if(( error = ak_hash_context_create_streebog512( &pctx->ctx )) != ak_error_ok )
      return ak_error_message( error, __func__, "invalid creation of streebog256 context ");
  }

 /* устанавливаем эллиптическую кривую */
  pctx->wc = ( ak_wcurve ) wc;

 /* копируем данные */
  blen = wc->size*sizeof( ak_uint64 );
  memset( pctx->qpoint.x, 0, 2*blen );
  memcpy( pctx->qpoint.x, key, blen );

  memset( pctx->qpoint.y, 0, 2*blen );
  memcpy( pctx->qpoint.y, ((ak_uint64 *)key)+wc->size, blen );

  memset( pctx->qpoint.z, 0, sizeof( pctx->qpoint.z ));
  pctx->qpoint.z[0] = 1;

#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < pctx->wc->size; i++ ) {
    pctx->qpoint.x[i] = bswap_64( pctx->qpoint.x[i] );
    pctx->qpoint.y[i] = bswap_64( pctx->qpoint.y[i] );
  }
#endif
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
    возникла ошибка, то возвращается ложь. Код шибки может получен с помощью
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

  memcpy( r, ( ak_uint64* )sign, sizeof( ak_uint64 )*pctx->wc->size );
  memcpy( s, ( ak_uint64 *)sign + pctx->wc->size, sizeof( ak_uint64 )*pctx->wc->size );
  memcpy( h, hash, sizeof( ak_uint64 )*pctx->wc->size );

#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < pctx->wc->size; i++ ) {
     r[i] = bswap_64( r[i] );
     s[i] = bswap_64( s[i] );
     h[i] = bswap_64( h[i] );
  }
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

  if( ak_mpzn_cmp( cpoint.x, r, pctx->wc->size )) return ak_false;
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа.
    @param in область памяти для которой проверяется электронная подпись.
    @param size размер области памяти в байтах.
    @param sign электронная подпись, для которой выполняется проверка.
    @return Функция возыращает истину, если подпись верна. Если функция не верна или если
    возникла ошибка, то возвращается ложь. Код шибки может получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_verifykey_context_verify_ptr( ak_verifykey pctx, const ak_pointer in,
                                                               const size_t size, ak_pointer sign )
{
  ak_uint8 hash[64];
  int error = ak_error_ok;

 /* необходимые проверки */
  if( pctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return ak_false;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to verifying value" );
    return ak_false;
  }
  if( pctx->ctx.hsize > 64 ) {
    ak_error_message( ak_error_wrong_length, __func__,
                                            "using hash function with large hash code size" );
    return ak_false;
  }

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, 64 );
  ak_hash_context_ptr( &pctx->ctx, in, size, hash );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return ak_false;
  }

 return ak_verifykey_context_verify_hash( pctx, hash, pctx->ctx.hsize, sign );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа.
    @param in область памяти для которой проверяется электронная подпись.
    @param size размер области памяти в байтах.
    @param sign электронная подпись, для которой выполняется проверка.
    @return Функция возыращает истину, если подпись верна. Если функция не верна или если
    возникла ошибка, то возвращается ложь. Код шибки может получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_verifykey_context_verify_file( ak_verifykey pctx, const char *filename, ak_pointer sign )
{
  ak_uint8 hash[64];
  int error = ak_error_ok;

 /* необходимые проверки */
  if( pctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return ak_false;
  }
  if( filename == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );
    return ak_false;
  }
  if( pctx->ctx.hsize > 64 ) {
    ak_error_message( ak_error_wrong_length, __func__,
                                            "using hash function with large hash code size" );
    return ak_false;
  }
  memset( hash, 0, 64 );
  ak_hash_context_file( &pctx->ctx, filename, hash );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return ak_false;
  }

 return ak_verifykey_context_verify_hash( pctx, hash, pctx->ctx.hsize, sign );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_verify_context_export_ptr( ak_verifykey pctx, ak_pointer out, size_t size )
{
#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
  size_t blen = 0;

 /* необходимые проверки */
  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to public key context" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to output buffer" );
  blen = pctx->wc->size*sizeof( ak_uint64 );
  if( size < 2*blen )
    return ak_error_message( ak_error_wrong_length, __func__, "using buffer with small size" );

 /* копируем данные */
  memcpy( out, pctx->qpoint.x, blen );
  memcpy( ((ak_uint64 *)out)+pctx->wc->size, pctx->qpoint.y, blen );

#ifndef LIBAKRYPT_LITTLE_ENDIAN
  for( i = 0; i < 2*pctx->wc->size; i++ ) ((ak_uint64 *)out)[i] = bswap_64( ((ak_uint64 *)out)[i] );
#endif

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                         тестовые примеры                                        */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция тестирует полный цикл: создание ключа, подпись, проверка для всех кривых
    заданного размера (256 или 512 бит).

    @return Функция возвращает истину только в том случае,
    когда будут пройдены все тесты. В противном случае возвращается ложь.                          */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_signkey_test_random_signatures( void )
{
  size_t count = 0, allcount = 0;
  ak_uint8 buffer[128];
  struct random generator;
  int error = ak_error_ok;
  bool_t result = ak_false;
  ak_oid oid = ak_oid_context_find_by_engine( identifier );

  /* создаем тестовый генератор */
   if(( error = ak_random_context_create_lcg( &generator )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of random generator" );
     goto labexit;
   }

  /* перебираем все эллиптические кривые в короткой форме Вейерштрасса  */
   while( oid != NULL ) {
     if( oid->mode == wcurve_params ) {
       ak_wcurve ec = ( ak_wcurve ) oid->data;
       struct signkey skey;
       struct verifykey vkey;

      /* теперь полный тест для одной кривой */
       allcount++;
       switch( ec->size ) {
         case ak_mpzn256_size:
           if(( error = ak_signkey_context_create_streebog256( &skey, ec )) != ak_error_ok ) {
             ak_error_message( error, __func__, "incorrect creation of secret key context" );
             goto labexit;
           }
           break;
         case ak_mpzn512_size:
           if(( error = ak_signkey_context_create_streebog512( &skey, ec )) != ak_error_ok ) {
             ak_error_message( error, __func__, "incorrect creation of secret key context" );
             goto labexit;
           }
           break;
         default:
           ak_error_message( ak_error_wrong_length, __func__, "invalid value of size parameter" );
           goto labexit;
       }

       if(( error = ak_signkey_context_set_key_random( &skey, &generator )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect assigning a secret key value" );
         ak_signkey_context_destroy( &skey );
         goto labexit;
       }

       if(( error = ak_verifykey_context_create_from_signkey( &vkey, &skey )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect creation of public key value" );
         ak_signkey_context_destroy( &skey );
         goto labexit;
       }

      /* только теперь создаем ЭП, а потом проверем */
       ak_signkey_context_sign_ptr( &skey, "1234567890", 10, buffer );
       result = ak_verifykey_context_verify_ptr( &vkey, "1234567890", 10, buffer );

       ak_verifykey_context_destroy( &vkey );
       ak_signkey_context_destroy( &skey );
       if( !result ) {
         ak_error_message_fmt( ak_error_not_equal_data, __func__,
             "wrong checking of digital signature for \"%s\" elliptic curve", oid->name );
         goto labexit;
       } else count++;
     }
     oid = ak_oid_context_findnext_by_engine( oid, identifier );
   }
   result = ak_true;

 labexit:
  error = ak_error_get_value();
  if(( count > 0 ) && ( ak_log_get_level() >= ak_log_maximum ))
    ak_error_message_fmt( ak_error_ok, __func__,
       "executing a %u successfull tests from %u for all predefined elliptic curves",
                                                                        count, allcount );
  if( !result ) ak_error_message( error, __func__,
        "testing a creation and verification processes from GOST R 34.10-2012 is wrong" );
  ak_random_context_destroy( &generator );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_signkey_test( void )
{
 /* секретные ключи определяются последовательностями байт */
 /* d = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"; */
  ak_uint8 key256[32] = {
   0x28, 0x3B, 0xEC, 0x91, 0x98, 0xCE, 0x19, 0x1D, 0xEE, 0x7E, 0x39, 0x49, 0x1F, 0x96, 0x60, 0x1B,
   0xC1, 0x72, 0x9A, 0xD3, 0x9D, 0x35, 0xED, 0x10, 0xBE, 0xB9, 0x9B, 0x78, 0xDE, 0x9A, 0x92, 0x7A };

 /* d = BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4 */
  ak_uint8 key512[64] = {
   0xd4, 0x8d, 0xa1, 0x1f, 0x82, 0x67, 0x29, 0xc6, 0xdf, 0xaa, 0x18, 0xfd, 0x7b, 0x6b, 0x63, 0xa2,
   0x14, 0x27, 0x7e, 0x82, 0xd2, 0xda, 0x22, 0x33, 0x56, 0xa0, 0x00, 0x22, 0x3b, 0x12, 0xe8, 0x72,
   0x20, 0x10, 0x8b, 0x50, 0x8e, 0x50, 0xe7, 0x0e, 0x70, 0x69, 0x46, 0x51, 0xe8, 0xa0, 0x91, 0x30,
   0xc9, 0xd7, 0x56, 0x77, 0xd4, 0x36, 0x09, 0xa4, 0x1b, 0x24, 0xae, 0xad, 0x8a, 0x04, 0xa6, 0x0b };

 /* промежуточные значения являются большими целыми числами и, следовательно,
    представляются в виде последовательности коэффициентов в системе счисления по основанию 2^64  */
 /* е = 2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5 */
  ak_uint64 e256[ak_mpzn256_size]  =
    { 0x67ECE6672B043EE5LL, 0xCE52032AB1022E8ELL, 0x88C09C52E0EEC61FLL, 0x2DFBC1B372D89A11LL };

 /* е = 3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C */
  ak_uint64 e512[ak_mpzn512_size]  =
    { 0xC6777D2972075B8CLL, 0x407ADEDB1D560C4FLL, 0x4339976C647C5D5ALL, 0x7184EE536593F441,
      0xA71D147035B0C591LL, 0x1B09B6F9C170C533LL, 0x5C4F4A7C4D8DAB53LL, 0x3754F3CFACC9E061 };

 /* k = 77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3 */
  ak_uint64 k256[ak_mpzn256_size]  =
    { 0x4FED924594DCEAB3LL, 0x6DE33814E95B7FE6LL, 0x2823C8CF6FCC7B95LL, 0x77105C9B20BCD312LL };

 /* k = 359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1 */
  ak_uint64 k512[ak_mpzn512_size]  =
    { 0xA3AF71BB1AE679F1LL, 0x212273A6D14CF70ELL, 0x4434006011842286LL, 0x86748ED7A44B3E79LL,
      0xD455986E364F3658LL, 0x946312120B39D019LL, 0xCC570456C6801496LL, 0x0359E7F4B1410FEALL };

 /* результирующие последовательности - электронные подписи, также представляются последовательностями байт */
  ak_uint8 sign256[64] =
    { 0x93, 0x04, 0xDC, 0x39, 0xFD, 0x43, 0xD0, 0x3A, 0xB8, 0x67, 0x27, 0xA4, 0x54, 0x35, 0x05, 0x74,
      0x19, 0xA4, 0xED, 0x6F, 0xD5, 0x9E, 0xCD, 0x80, 0x82, 0x14, 0xAB, 0xF1, 0xD2, 0x28, 0xAA, 0x41,
      0x40, 0x9C, 0xBF, 0xC5, 0xF6, 0x14, 0x80, 0x92, 0xDF, 0x31, 0xB6, 0x46, 0xF7, 0xD3, 0xD6, 0xBC,
      0x49, 0x02, 0xA6, 0x98, 0x5A, 0x23, 0x3C, 0x65, 0xA1, 0x42, 0x46, 0xBA, 0x64, 0x6C, 0x45, 0x01 };

  ak_uint8 sign512[128] =
    { 0x36, 0xAE, 0x73, 0xE1, 0x44, 0x93, 0xE1, 0x17, 0x33, 0x5C, 0x9C, 0xCD, 0xCB, 0x3B, 0xC9, 0x60,
      0x02, 0x85, 0x99, 0x06, 0xC9, 0x97, 0xC1, 0x9E, 0x1C, 0x0F, 0xB2, 0x86, 0x84, 0x55, 0x92, 0x54,
      0xD3, 0xAC, 0xFC, 0xA8, 0xEE, 0x78, 0x3C, 0x64, 0xC2, 0xDC, 0xE0, 0x2E, 0xC8, 0xA3, 0x12, 0xE5,
      0x9E, 0x68, 0x3C, 0x1E, 0x5E, 0x79, 0xDD, 0x23, 0x1A, 0x09, 0x81, 0xA0, 0x60, 0xFA, 0x86, 0x2F,
      0x4A, 0x5B, 0x3E, 0xE7, 0xBD, 0x53, 0x98, 0x2A, 0xB9, 0x9C, 0x91, 0x56, 0x1F, 0xEB, 0x6E, 0x6A,
      0x40, 0xCE, 0x70, 0x7F, 0xDF, 0x80, 0x60, 0x52, 0x62, 0xF3, 0xC4, 0xE8, 0x88, 0xE2, 0x3C, 0x82,
      0xF5, 0x2F, 0xD5, 0x33, 0xE9, 0xFB, 0x0B, 0x1C, 0x08, 0xBC, 0xAD, 0x8A, 0x77, 0x56, 0x5F, 0x32,
      0xB6, 0x26, 0x2D, 0x36, 0xA9, 0xE7, 0x85, 0x65, 0x8E, 0xFE, 0x6F, 0x69, 0x94, 0xB3, 0x81, 0x10 };

#ifndef LIBAKRYPT_LITTLE_ENDIAN
  int i = 0;
#endif
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

  if(( error = ak_signkey_context_set_key( &sk, key256, sizeof( key256 ), ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a constant key value" );
    ak_signkey_context_destroy( &sk );
    return ak_false;
  }

  memset( sign, 0, 64 );
  ak_signkey_context_sign_const_values( &sk, k256, e256, sign );
  if( ak_ptr_is_equal( sign, ( ak_pointer )sign256, 64 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature generation process from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature generation process from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr(( ak_pointer )sign256, 64, ak_true ))); free( str );
      ak_signkey_context_destroy( &sk );
      return ak_false;
    }

  if(( error = ak_verifykey_context_create_from_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_context_destroy( &sk );
    return ak_false;
  }
  ak_signkey_context_destroy( &sk );

  /* поскольку проверка выполняется для результата функции хеширования, то мы
     преобразуем последовательность 64х битных интов в последовательность байт */
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  memcpy( e, e256, 32 );
#else
  for( i = 0; i < ak_mpzn256_size; i++ ) ((ak_uint64 *)e)[i] = bswap_64( e256[i] );
#endif

  if( ak_verifykey_context_verify_hash( &pk, e, 32, sign )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification process from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification process from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_verifykey_context_destroy( &pk );
      return ak_false;
  }
  ak_verifykey_context_destroy( &pk );

 /* 2. Второй пример из приложения А ГОСТ Р 34.10-2012. */
  if(( error = ak_signkey_context_create_streebog512( &sk,
    (ak_wcurve) &id_tc26_gost_3410_2012_512_paramSetTest )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,
             "incorrect creation of 512 bits secret key for GOST R 34.10-2012" );
    return ak_false;
  }

  if(( error = ak_signkey_context_set_key( &sk, key512, sizeof( key512 ), ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a constant key value" );
    ak_signkey_context_destroy( &sk );
    return ak_false;
  }

  memset( sign, 0, 128 );
  ak_signkey_context_sign_const_values( &sk, k512, e512, sign );
  if( ak_ptr_is_equal( sign, ( ak_pointer )sign512, 128 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature generation process from GOST R 34.10-2012 (for 512 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature generation process from GOST R 34.10-2012 (for 512 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 128, ak_true ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr(( ak_pointer )sign512, 128, ak_true ))); free( str );
      ak_signkey_context_destroy( &sk );
      return ak_false;
    }

  if(( error = ak_verifykey_context_create_from_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_context_destroy( &sk );
    return ak_false;
  }
  ak_signkey_context_destroy( &sk );

  /* поскольку проверка выполняется для результата функции хеширования, то мы
     преобразуем последовательность 64х битных интов в последовательность байт */
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  memcpy( e, e512, 64 );
#else
  for( i = 0; i < ak_mpzn512_size; i++ ) ((ak_uint64 *)e)[i] = bswap_64( e512[i] );
#endif

  if( ak_verifykey_context_verify_hash( &pk, e, 64, sign )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification process from GOST R 34.10-2012 (for 512 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification process from GOST R 34.10-2012 (for 512 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_verifykey_context_destroy( &pk );
      return ak_false;
  }
  ak_verifykey_context_destroy( &pk );

 /* 3. Тестирование случайно сгенеренных электронных подписей для всех определенных
                                                                              эллиптических кривых */
  if( !ak_signkey_test_random_signatures( )) return ak_false;

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_get_value(), __func__ ,
                                                "testing digital signatures ended successfully" );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-internal-sign01.c
 *  \example test-internal-sign02.c                                                                */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.c  */
/* ----------------------------------------------------------------------------------------------- */
