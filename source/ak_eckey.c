/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
/*   ak_eckey.c                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_skey.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция накладывает мультипликативную маску на ключ. Для ключа \f$ k \f$
    его маской является пара значений \f$ kc \pmod{q}, c^{-1} \pmod{q} \f$,
    где \f$ c \f$ произвольная, отличная от нуля константа, а \f$ q \f$
    порядок группы точек эллиптической кривой, в которой производятся криптографические вычисления */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_mask_multiplicative( ak_skey skey )
{
  int error = ak_error_ok;
  size_t len = 0;
  ak_mpznmax q;

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
 /* проверяем длину ключа */
  len = strlen((( ak_wcurve_paramset )skey->data)->cq ) >> 1;
  if( skey->key.size != len ) return ak_error_message( ak_error_wrong_length, __func__,
                                                           "using a key buffer with wrong length" );
 /* создаем маску */
  if( ak_random_ptr( skey->generator, skey->mask.data, skey->mask.size >> 1 ) != ak_error_ok )
    return ak_error_message( ak_error_write_data, __func__ ,
                                                           "wrong mask generation for key buffer" );
  if(( error = ak_mpzn_set_hexstr( q,
                  len/sizeof( ak_uint64 ), ((ak_wcurve_paramset) skey->data)->cq )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong convertation of elliptic curve module" );

  ak_mpzn_rem( skey->key.data, skey->key.data, q, len/sizeof( ak_uint64 ));
  ak_mpzn_rem( skey->mask.data, skey->mask.data, q, len/sizeof( ak_uint64 ));

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
 int ak_ecskey_create( ak_ecskey ekey, ak_wcurve_paramset paramset )
{
  size_t len = 0;
  int error = ak_error_ok;

  if( ekey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using a null pointer to asymmetric secret context" );
  if( paramset == NULL ) return ak_error_message( ak_error_undefined_value, __func__,
                                             "using a null pointer to elliptic curve parameters" );
  len = strlen( paramset->cq ) >> 1;
  if(( len != 32 ) || ( len != 64 )) return ak_error_message( ak_error_wrong_length,
                    __func__, "using elliptic curve parameters with wrong length of group order" );
  if(( error = ak_skey_create( &ekey->key, len, len << 1 )) != ak_error_ok )
             return ak_error_message( error, __func__, "wrong creation an asymmetric secret key" );

 /* указатель на параметры эллиптической кривой не размножается, а просто копируется
    позднее надо не забыть обнулить указатель,
    поскольку в противном случае в ak_skey_destroy для него будет вызываться free */
  ekey->key.data = paramset;

  ekey->key.set_mask = ak_skey_set_mask_multiplicative;
  ekey->key.remask = ak_skey_remask_multiplicative;
  ekey->key.set_icode = ak_skey_set_icode_multiplicative;
  ekey->key.check_icode = ak_skey_check_icode_multiplicative;

 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_eckey.c  */
/* ----------------------------------------------------------------------------------------------- */
