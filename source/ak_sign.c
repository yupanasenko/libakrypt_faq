/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_sign.h                                                                                 */
/*  - содержит реализацию функций для работы с электронной подписью.                               */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_sign.h>
 #include <ak_parameters.h>
 #include <ak_context_manager.h>

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
                                           skey->mask.data, skey->mask.size )) != ak_error_ok )
     return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

    /* накладываем маску на ключ
      - для этого мы вычисляем значение маски M^{-1} mod(q), хранящееся в skey->mask,
        и присваиваем ключу K значение KM mod(q)
      - при этом значения ключа и маски хранятся в представлении Монтгомери    */

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
     if(( error = ak_random_context_random( &skey->generator, zeta, skey->mask.size )) != ak_error_ok )
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
 /* меняем значение флага */
  skey->flags ^= skey_flag_set_mask;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @todo Необходимо реализовать выработку контрольной суммы для секретного ключа ЭП. */
 static int ak_signkey_context_set_icode_multiplicative( ak_skey skey )
{
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @todo Необходимо реализовать проверку контрольной суммы для секретного ключа ЭП. */
 static ak_bool ak_signkey_context_check_icode_multiplicative( ak_skey skey )
{
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
 int ak_signkey_context_create_streebog256( ak_signkey sctx, ak_wcurve wc )
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
   if(( sctx->key.oid = ak_oid_context_find_by_name( "sign256" )) == NULL )
     ak_error_message( ak_error_get_value(), __func__ ,
                                                     "incorrect initialization of algorithm " );
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
 int ak_signkey_context_create_streebog512( ak_signkey sctx, ak_wcurve wc )
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
   if(( sctx->key.oid = ak_oid_context_find_by_name( "sign512" )) == NULL )
     ak_error_message( ak_error_get_value(), __func__ ,
                                                     "incorrect initialization of algorithm " );
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
 int ak_signkey_context_create_gosthash94_csp( ak_signkey sctx, ak_wcurve wc )
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
   if(( error = ak_hash_context_create_gosthash94_csp( &sctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_context_create( &sctx->key, sctx->ctx.hsize, 8 )) != ak_error_ok ) {
     ak_hash_context_destroy( &sctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* устанавливаем OID алгоритма */
   if(( sctx->key.oid = ak_oid_context_find_by_name( "sign256-gosthash94" )) == NULL )
     ak_error_message( ak_error_get_value(), __func__ ,
                                                     "incorrect initialization of algorithm " );
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

 return ((ak_function_create_signkey *)algoid->func.create)( sctx, (ak_wcurve ) curveoid->data );
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
 const size_t ak_signkey_context_get_code_size( ak_signkey sctx )
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
    @param size размер ключа в байтах.
    @param cflag Флаг передачи владения указателем `ptr`. Если `cflag` ложен (принимает значение `ak_false`),
    то физического копирования данных не происходит: внутренний буфер лишь указывает на размещенные
    в другом месте данные, но не владеет ими. Если `cflag` истиннен (принимает значение `ak_true`),
    то происходит выделение памяти и копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_set_key( ak_signkey sctx, const ak_pointer ptr,
                                                            const size_t size, const ak_bool cflag )
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
    формируется электронная подпись, представляющая собой конкатенацию векторов \f$ r||s \f$.

    \b Внимание! Входные параметры функции не проверяются.

    @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param k степень кратности точки \f$ P \f$; представляет собой вычет по модулю \f$ q \f$ - порядка
           группы точек эллиптической кривой;
           при вычислении подписи предполагается, что под вычет выделена память в количестве
           `wc->size` слов размера 64 бита, где `wc` используемая эллиптическая кривая.

    @param e хеш-код сообщения, для которого вырабатывается электронная подпись.
    @param out массив, куда помещается результат. Память под массив должна быть выделена заранее.  */
/* ----------------------------------------------------------------------------------------------- */
 void ak_signkey_context_sign_const_values( ak_signkey sctx,
                                                       ak_uint64 *k, ak_pointer e, ak_pointer out )
{
 /* поскольку функция не экспортируется, мы оставляем все проверки функциям верхнего уровня */
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;
  ak_uint64 *r = (ak_uint64 *)out, *s = ( ak_uint64 *)out + wc->size;

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
  ak_mpzn_rem( wr.z, (ak_uint64 *)e, wc->q, wc->size );
  if( ak_mpzn_cmp_ui( wr.z, wc->size, 0 )) ak_mpzn_set_ui( wr.z, wc->size, 1 );
  ak_mpzn_mul_montgomery( wr.z, wr.z, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем k*e (mod q) и вычисляем s = r*d + k*e (mod q) (в форме Монтгомери) */
  ak_mpzn_mul_montgomery( wr.y, wr.y, wr.z, wc->q, wc->nq, wc->size ); /* wr.y <- k*e */
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

 /* приводим s к обычной форме */
  ak_mpzn_mul_montgomery( s, s,  wc->point.z, /* для экономии памяти пользуемся равенством z = 1 */
                                 wc->q, wc->nq, wc->size );
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
  ak_pointer pout = out;
  ak_buffer result = NULL;
  int error = ak_error_ok;
  ak_uint64 k[ak_mpzn512_size];
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

 /* и только теперь вычисляем электронную подпись */
  ak_signkey_context_sign_const_values( sctx, k, hash, pout );

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
/*                                         тестовые примеры                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_signkey_test( void )
{
 /* d = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"; */
  ak_uint64 key256[ak_mpzn256_size]  =
    { 0x1D19CE9891EC3B28LL, 0x1B60961F49397EEELL, 0x10ED359DD39A72C1LL, 0x7A929ADE789BB9BELL };

 /* d = BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4 */
  ak_uint64 key512[ak_mpzn512_size]  =
    { 0xC62967821FA18DD4LL, 0xA2636B7BFD18AADFLL, 0x3322DAD2827E2714LL, 0x72E8123B2200A056LL,
      0x0EE7508E508B1020LL, 0x3091A0E851466970LL, 0xA40936D47756D7C9LL, 0x0BA6048AADAE241BLL };

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

  struct signkey sk;
  ak_uint8 sign[128];
 /* struct verifykey pk; */
  char *str = NULL;
  int error = ak_error_ok, audit = ak_log_get_level();

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing digital signatures started" );

 /* 1. первый пример из приложения А ГОСТ Р 34.10-2012. */
  if(( error = ak_signkey_context_create_streebog256( &sk,
    (ak_wcurve) &id_tc26_gost_3410_2012_256_paramSetTest )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature secret key" );
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
  ak_signkey_context_destroy( &sk );

/*
  if(( error = ak_verifykey_create_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }

  if( ak_verifykey_context_verify_hash( &pk, e256, sizeof(e256), sign )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_verifykey_destroy( &pk );
      return ak_false;
  }
  ak_verifykey_destroy( &pk );
*/

 /* 2. Тестирование случайно сгенеренных электронных подписей для всех 256 битных кривых */

 /* 3. Второй пример из приложения А ГОСТ Р 34.10-2012. */
  if(( error = ak_signkey_context_create_streebog512( &sk,
    (ak_wcurve) &id_tc26_gost_3410_2012_512_paramSetTest )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature secret key" );
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
  ak_signkey_context_destroy( &sk );

/*
  if(( error = ak_verifykey_create_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }

  if( ak_verifykey_context_verify_hash( &pk, e512, sizeof(e512),  sign )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification from GOST R 34.10-2012 (for 512 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification from GOST R 34.10-2012 (for 512 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_verifykey_destroy( &pk );
      return ak_false;
  }
  ak_verifykey_destroy( &pk );
*/

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_get_value(), __func__ ,
                                                "testing digital signatures ended successfully" );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.c  */
/* ----------------------------------------------------------------------------------------------- */
