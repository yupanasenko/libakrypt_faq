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
    и случайного числа \f$ k \f$. Для этого

     - вычисляется точка \f$ C = [k]P\f$, где \f$ P \f$ точка, порождающая подгруппу простого
       порядка \f$ q \f$.
     - точка приводитя к аффинной форме и для х-координаты точки \f$ C \f$ вычисляется значение
       \f$ r \equiv x \pmod{q}\f$.
     - вычисляется вторая половинка подписи  \f$ s \f$,
       удовлетворяющая сравнению \f$ s \equiv rd + ke \pmod{q}\f$.

    После этого
    формируется электронная подпись, представляющая собой конкатенацию \f$ r||s \f$.

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
  struct wpoint wp, wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;
  ak_uint64 *r = (ak_uint64 *)out, *s = ( ak_uint64 *)out + wc->size;
  ak_mpznmax one = ak_mpznmax_one;
  char *str = NULL;

 /* вычисляем r */
  ak_wpoint_set( &wp, wc );
  ak_wpoint_pow( &wr, &wp, k, wc->size, wc );
  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );
  printf("sign   (r): %s\n", str = ak_ptr_to_hexstr( r, 32, ak_true )); free( str );

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

  ak_mpzn_mul_montgomery( s, s, one, wc->q, wc->nq, wc->size );
  printf("sign   (s): %s\n", str = ak_ptr_to_hexstr( s, 32, ak_true )); free( str );

 /* завершаемся */
  sctx->key.remask( &sctx->key );
 return NULL;
}



/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.c  */
/* ----------------------------------------------------------------------------------------------- */
