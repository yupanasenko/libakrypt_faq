/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2008 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_sign.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_sign.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_create_streebog256( ak_signkey sctx, ak_wcurve wc )
{
 int error = ak_error_ok;

 if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
 if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using null pointer to elliptic curve context" );
 if( wc->size != 4 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                       "elliptic curve defined over wrong field" );

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_streebog256( &sctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &sctx->key, sctx->ctx.hsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &sctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* устанавливаем эллиптическую кривую */
   sctx->key.data = wc;

  /* устанавливаем OID алгоритма */
   sctx->key.oid = NULL;

  /* При удалении ключа не нужно освобождать память из под параметров эллиптической кривой  */
   sctx->key.flags |= ak_skey_flag_data_nonfree;

 /* в заключение определяем указатели на методы */
  sctx->key.set_mask = ak_skey_set_mask_ladditive;
  sctx->key.remask = ak_skey_remask_ladditive;
  sctx->key.set_icode = ak_skey_set_icode_ladditive;
  sctx->key.check_icode = ak_skey_check_icode_ladditive;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_destroy( ak_signkey sctx )
{
  int error = ak_error_ok;
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                           "destroying a null pointer to digital signature secret key context" );
  if(( error = ak_skey_destroy( &sctx->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying of digital signature secret key" );
  if(( error = ak_hash_destroy( &sctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying hash function context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_signkey_delete( ak_pointer sctx )
{
  if( sctx != NULL ) {
      ak_signkey_destroy(( ak_signkey ) sctx );
      free( sctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                   "using null pointer to digital signature secret key context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_set_key( ak_signkey sctx, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;

  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to constant key value" );
  if( size > sctx->key.key.size ) return ak_error_message( ak_error_wrong_length, __func__,
                                                   "using constant buffer with unexpected length");
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_set_ptr( &sctx->key, ptr, size, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of key data" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает электронную подпись для хеш-кода подписываемого сообщения \f$ e \f$
    и заданного случайного числа \f$ k \f$. Для этого

     - вычисляется точка \f$ C = [k]P\f$, где \f$ P \f$ точка, порождающая подгруппу простого
       порядка \f$ q \f$.
     - точка приводитя к аффинной форме и для х-координаты точки \f$ C \f$ вычисляется значение
       \f$ r \equiv x \pmod{q}\f$.
     - вычисляется вторая половинка подписи  \f$ s \f$,
       удовлетворяющая сравнению \f$ s \equiv rd + ke \pmod{q}\f$.

    После этого
    формируется электронная подпись, представляющая собой конкатенацию векторов \f$ r||s \f$.

    \b Внимание! Входные параметры функции не проверяются.

    @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param k степень кратности точки \f$ P \f$.
    @param e хеш-код сообщения, для которого вырабатывается электронная подпись.
    @param out массив, куда помещается результат. Память под массив должна быть выделена заранее.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_signkey_context_sign_values( ak_signkey sctx, ak_uint64 *k,
                                                                      ak_pointer e, ak_pointer out )
{
 /* поскольку функция не экспортируется, мы оставляем все проверки функциям верхнего уровня */
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;
  ak_uint64 *r = (ak_uint64 *)out, *s = ( ak_uint64 *)out + wc->size;

 /* вычисляем r */
  ak_wpoint_pow( &wr, &wc->point, k, wc->size, wc );
  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );

 /* вычисляем s */
  ak_mpzn_mul_montgomery( wr.x, r, wc->r2q, wc->q, wc->nq, wc->size );
  ak_mpzn_mul_montgomery( s, wr.x, sctx->key.key.data, wc->q, wc->nq, wc->size ); /* s <- r*d */

  ak_mpzn_mul_montgomery( wr.y, k, wc->r2q, wc->q, wc->nq, wc->size );
  ak_mpzn_mul_montgomery( wr.z, (ak_uint64 *)e, wc->r2q, wc->q, wc->nq, wc->size );
  ak_mpzn_mul_montgomery( wr.y, wr.y, wr.z, wc->q, wc->nq, wc->size ); /* wr.y <- k*e */
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

  ak_mpzn_mul_montgomery( wr.x, wr.x, sctx->key.mask.data, wc->q, wc->nq, wc->size );
  ak_mpzn_sub( wr.y, wc->q, wr.x, wc->size );
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

  ak_mpzn_mul_montgomery( s, s,  wc->point.z, /* для экономии памяти пользуемся равенством z = 1 */
                                 wc->q, wc->nq, wc->size );
 /* завершаемся */
  sctx->key.remask( &sctx->key );
 return NULL;
}



/* ----------------------------------------------------------------------------------------------- */
/*                       Функции для работы с открытыми ключами                                    */
/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст секретного ключа алгоритма электронной подписи.
    @param wc контекст эллиптической кривой.

    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_pubkey_create_streebog256( ak_pubkey pctx, ak_wcurve wc )
{
  int error = ak_error_ok;

  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                     "using null pointer to digital signature public key context" );
  if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                   "using null pointer to elliptic curve context" );
  if( wc->size != 4 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                        "elliptic curve defined over wrong field" );
 /* инициализируем контекст функции хеширования */
  if(( error = ak_hash_create_streebog256( &pctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid creation of hash function context");

 /* устанавливаем эллиптическую кривую */
  pctx->wc = wc;

 /* устанавливаем OID алгоритма */
  pctx->oid = NULL;

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
 int ak_pubkey_create_signkey( ak_pubkey pctx, ak_signkey sctx )
{
  struct wpoint tpoint;
  int error = ak_error_ok;
  ak_mpzn512 t = ak_mpzn512_zero;

  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                            "using null pointer to digital signature public key context" );
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using a null pointer to hmac key context" );

  if(( error = ak_hash_create_oid( &pctx->ctx, sctx->ctx.oid )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid creation of hash function context");

 /* устанавливаем эллиптическую кривую */
  pctx->wc = ( ak_wcurve )sctx->key.data;

 /* устанавливаем OID алгоритма */
  pctx->oid = NULL;

 /* теперь определяем открытый ключ */
  ak_mpzn_mul_montgomery( t, (ak_uint64 *)sctx->key.key.data, pctx->wc->point.z, /* пользуемся z = 1 */
                             pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_wpoint_pow( &pctx->qpoint, &pctx->wc->point, t, pctx->wc->size, pctx->wc );

  ak_mpzn_mul_montgomery( t, (ak_uint64 *)sctx->key.mask.data, pctx->wc->point.z, /* пользуемся z = 1 */
                             pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_wpoint_pow( &tpoint, &pctx->wc->point, t, pctx->wc->size, pctx->wc );
  ak_mpzn_sub( tpoint.y, pctx->wc->p, tpoint.y, pctx->wc->size );
  ak_wpoint_add( &pctx->qpoint, &tpoint, pctx->wc );
  ak_wpoint_reduce( &pctx->qpoint, pctx->wc );
  sctx->key.remask( &sctx->key );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа алгоритма электронной подписи.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_pubkey_destroy( ak_pubkey pctx )
{
  int error = ak_error_ok;

  if( pctx == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to public key context" );
  if(( error = ak_hash_destroy( &pctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying hash function context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа алгоритма электронной подписи.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_pubkey_delete( ak_pointer pctx )
{
  if( pctx != NULL ) {
      ak_pubkey_destroy(( ak_pubkey ) pctx );
      free( pctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                   "using null pointer to digital signature public key context" );
 return NULL;
}


/* ----------------------------------------------------------------------------------------------- */
/*!
    \b Внимание! Входные параметры функции не проверяются.

    @param pctx контекст открытого ключа.
    @param sign электронная подпись, для которой выполняется проверка.
    @param e хеш-код сообщения, для которого проверяется электронная подпись.
    @return Функция возыращает истину, если подпись верна. Если функция не верна или если
    возникла ошибка, то возвращается ложь. Код шибки может получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_pubkey_context_verify_values( ak_pubkey pctx, ak_pointer sign, ak_pointer e )
{
  ak_mpzn512 v, z1, z2, u;
  struct wpoint cpoint, tpoint;
  ak_uint64 *r = (ak_uint64 *)sign, *s = ( ak_uint64 *)sign + pctx->wc->size;

  ak_mpzn_set( v, e, pctx->wc->size );
  ak_mpzn_rem( v, v, pctx->wc->q, pctx->wc->size );
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
 ak_bool ak_signkey_test( void )
{
 /* d = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"; */
  const ak_uint64 key256[ak_mpzn256_size]  =
    { 0x1D19CE9891EC3B28LL, 0x1B60961F49397EEELL, 0x10ED359DD39A72C1LL, 0x7A929ADE789BB9BELL };

 /* d = BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4 */
  const ak_uint64 key512[ak_mpzn512_size]  =
    { 0xC62967821FA18DD4LL, 0xA2636B7BFD18AADFLL, 0x3322DAD2827E2714LL, 0x72E8123B2200A056LL,
      0x0EE7508E508B1020LL, 0x3091A0E851466970LL, 0xA40936D47756D7C9LL, 0x0BA6048AADAE241BLL };

 /* е = 2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5 */
  const ak_uint64 e256[ak_mpzn256_size]  =
    { 0x67ECE6672B043EE5LL, 0xCE52032AB1022E8ELL, 0x88C09C52E0EEC61FLL, 0x2DFBC1B372D89A11LL };

 /* k = 77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3 */
  const ak_uint64 k256[ak_mpzn256_size]  =
    { 0x4FED924594DCEAB3LL, 0x6DE33814E95B7FE6LL, 0x2823C8CF6FCC7B95LL, 0x77105C9B20BCD312LL };

  const ak_uint8 sign256[64] =
    { 0x93, 0x04, 0xDC, 0x39, 0xFD, 0x43, 0xD0, 0x3A, 0xB8, 0x67, 0x27, 0xA4, 0x54, 0x35, 0x05, 0x74,
      0x19, 0xA4, 0xED, 0x6F, 0xD5, 0x9E, 0xCD, 0x80, 0x82, 0x14, 0xAB, 0xF1, 0xD2, 0x28, 0xAA, 0x41,
      0x40, 0x9C, 0xBF, 0xC5, 0xF6, 0x14, 0x80, 0x92, 0xDF, 0x31, 0xB6, 0x46, 0xF7, 0xD3, 0xD6, 0xBC,
      0x49, 0x02, 0xA6, 0x98, 0x5A, 0x23, 0x3C, 0x65, 0xA1, 0x42, 0x46, 0xBA, 0x64, 0x6C, 0x45, 0x01 };

  int error = ak_error_ok, audit = ak_log_get_level();
  ak_bool result = ak_true;
  struct signkey sk;
  struct pubkey pk;
  ak_uint8 sign[128];
  char *str = NULL;

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing digital signatures started" );

 /* первый пример из приложения А ГОСТ Р 34.10-2012. */
  if(( error = ak_signkey_create_streebog256( &sk,
    (ak_wcurve) &id_tc26_gost3410_2012_256_test_paramset )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature secret key" );
    return ak_false;
  }

  if(( error = ak_signkey_context_set_key( &sk, ( ak_pointer )key256, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }

  memset( sign, 0, 64 );
  ak_signkey_context_sign_values( &sk, ( ak_pointer )k256, ( ak_pointer )e256, sign );
  if( ak_ptr_is_equal( sign, ( ak_pointer )sign256, 64 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature generation from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature generation from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr(( ak_pointer )sign256, 64, ak_true ))); free( str );
      ak_signkey_destroy( &sk );
      return ak_false;
    }

  if(( error = ak_pubkey_create_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }

  ak_signkey_destroy( &sk );
  if( ak_pubkey_context_verify_values( &pk, sign, ( ak_pointer )e256 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_pubkey_destroy( &pk );
      return ak_false;
  }
  ak_pubkey_destroy( &pk );

 /* второй пример из приложения А ГОСТ Р 34.10-2012. */
  if(( error = ak_signkey_create_streebog512( &sk,
    (ak_wcurve) &id_tc26_gost3410_2012_512_test_paramset )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature secret key" );
    return ak_false;
  }

  ak_signkey_destroy( &sk );


  if( !result ) ak_error_message( ak_error_get_value(), __func__ ,
                                                         "incorrect testing digital signatures" );
   else if( audit >= ak_log_maximum ) ak_error_message( ak_error_get_value(), __func__ ,
                                                "testing digital signatures ended successfully" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.c  */
/* ----------------------------------------------------------------------------------------------- */
