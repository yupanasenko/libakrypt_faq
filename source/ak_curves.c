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
/*   ak_curves.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_curves.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляерт величину \f$\Delta \equiv -16(4a^3 + 27b^2) \pmod{p} \f$, зависящую
    от параметров эллиптической кривой

    @param d Вычет, в который помещается вычисленное значение.
    @param ec Контекст эллиптической кривой, для которой вычисляется ее дискриминант               */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_set_wcurve_static_discriminant( ak_uint64 *d, ak_wcurve_static ec )
{
  ak_mpznmax s, one = ak_mpznmax_one;

 /* определяем константы 4 и 27 в представлении Монтгомери */
  ak_mpzn_set_ui( d, ec->size, 4 );
  ak_mpzn_set_ui( s, ak_mpznmax_size, 27 );
  ak_mpzn_mul_montgomery( d, d, ec->r2, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->r2, ec->p, ec->n, ec->size );

 /* вычисляем 4a^3 (mod p) значение в представлении Монтгомери */
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );

 /* вычисляем значение 4a^3 + 27b^2 (mod p) в представлении Монтгомери */
  ak_mpzn_mul_montgomery( s, s, ec->b, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->b, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( d, d, s, ec->p, ec->size );

 /* определяем константу -16 в представлении Монтгомери и вычисляем D = -16(4a^3+27b^2) (mod p) */
  ak_mpzn_set_ui( s, ec->size, 16 );
  ak_mpzn_sub( s, ec->p, s, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->r2, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, s, ec->p, ec->n, ec->size );

 /* возвращаем результат (в обычном представлении) */
  ak_mpzn_mul_montgomery( d, d, one, ec->p, ec->n, ec->size );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_wcurve_static_discriminant_is_ok( ak_wcurve_static ec )
{
  ak_mpznmax d;
  if( ec == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                               "using a null pointer to elliptic curve context" );
  ak_mpzn_set_wcurve_static_discriminant( d, ec );
  if( ak_mpzn_cmp_ui( d, ec->size, 0 ) == ak_true ) return ak_error_curve_discriminant;
   else return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает на вход контекст эллиптической кривой, заданной в короткой форме Вейерштрасса,
    и выполняет следующие проверки

     - проверяется, что модуль кривой (простое число \f$ p \f$) удовлетворяет неравенству
       \f$ 2^{n-32} < p < 2^n \f$, где \f$ n \f$ это либо 256, либо 512 в зависимости от
       параметров кривой,
     - проверяется, что дискриминант кривой отличен от нуля по модулю \f$ p \f$,
     - проверяется, что фиксированная точка кривой, содержащаяся в контексте эллиптической кривой,
       действительно принадлежит эллиптической кривой,
     - проверяется, что порядок этой точки кривой равен простому числу \f$ q \f$,
       содержащемуся в контексте эллиптической кривой.

     @param ec контекст структуры эллиптической кривой, содержащий в себе значения параметров.
     Константные значения структур, которые могут быть использованы библиотекой,
     задаются в файле \ref ak_parameters.h

     @return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае,
     возвращается код ошибки.                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wcurve_static_is_ok( ak_wcurve_static ec )
{
  int error = ak_error_ok;
  struct wpoint_static wp;

 /* создали кривую и проверяем ее параметры */
  if( ec->p[ ec->size-1 ] < 0x100000000LL )
    return ak_error_message( ak_error_curve_prime_size, __func__ ,
                                            "using elliptic curve parameters with wrong module" );
  if(( error = ak_wcurve_static_discriminant_is_ok( ec )) != ak_error_ok )
    return ak_error_message( ak_error_curve_discriminant, __func__ ,
                                       "using elliptic curve parameters with zero discriminant" );
 /* теперь тестируем точку на кривой */
  if(( error = ak_wpoint_static_set( &wp, ec )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorect asiigning a temporary point" );
  if( ak_wpoint_static_is_ok( &wp, ec ) != ak_true )
    return ak_error_message( ak_error_curve_point, __func__ ,
                                               "elliptic curve parameters has'nt correct point" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выводит в файл аудита значения параметров эллиптической кривой                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_wcurve_static_to_log( ak_wcurve_static ec )
{
  char message[160];

  memset( message, 0, 160 );
  ak_snprintf( message, 160, " a = " );
  ak_ptr_to_hexstr_static( ec->a, ec->size*sizeof( ak_uint64 ), message+5, 155, ak_true );
  ak_log_set_message( message );

  memset( message, 0, 160 );
  ak_snprintf( message, 160, " b = " );
  ak_ptr_to_hexstr_static( ec->b, ec->size*sizeof( ak_uint64 ), message+5, 155, ak_true );
  ak_log_set_message( message );

  memset( message, 0, 160 );
  ak_snprintf( message, 160, " p = " );
  ak_ptr_to_hexstr_static( ec->p, ec->size*sizeof( ak_uint64 ), message+5, 155, ak_true );
  ak_log_set_message( message );

  memset( message, 0, 160 );
  ak_snprintf( message, 160, " q = " );
  ak_ptr_to_hexstr_static( ec->q, ec->size*sizeof( ak_uint64 ), message+5, 155, ak_true );
  ak_log_set_message( message );

  memset( message, 0, 160 );
  ak_snprintf( message, 160, "px = " );
  ak_ptr_to_hexstr_static( ec->px, ec->size*sizeof( ak_uint64 ), message+5, 155, ak_true );
  ak_log_set_message( message );

  memset( message, 0, 160 );
  ak_snprintf( message, 160, "py = " );
  ak_ptr_to_hexstr_static( ec->py, ec->size*sizeof( ak_uint64 ), message+5, 155, ak_true );
  ak_log_set_message( message );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Проверяются параметры всех эллиптических кривых, доступных через механизм OID.
    Проверка производится путем вызова функции ak_wcurve_is_ok().

    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения
    ошибки функция возвращает ak_false. Код ошибки можеть быть получен с помощью вызова
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_wcurve_static_test( void )
{
  ak_bool result = ak_true;
  ak_handle handle = ak_error_wrong_handle;
  int reason = ak_error_ok, audit = ak_log_get_level();

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing Weierstrass curves started" );

 /* организуем цикл по перебору всех известных библиотеке параметров эллиптических кривых */
  handle = ak_oid_find_by_engine( identifier );
  while( handle != ak_error_wrong_handle ) {
    if( ak_oid_get_mode( handle ) == ecurve_params ) {
      ak_oid oid = NULL;
      ak_wcurve_static wc = NULL;

      if(( oid = ak_handle_get_context( handle, oid_engine )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "internal error with wrong handle" );
        result = ak_false;
        goto lab_exit;
      }
      if(( wc = ( ak_wcurve_static ) oid->data ) == NULL )  {
        ak_error_message( ak_error_null_pointer, __func__,
                                      "internal error with null poionter to wcurve paramset" );
        result = ak_false;
        goto lab_exit;
      }
      ak_wcurve_static_to_log( wc );


      if(( reason = ak_wcurve_static_is_ok( wc )) != ak_error_ok ) {
        char *p = NULL;
        switch( reason ) {
          case ak_error_curve_discriminant : p = "discriminant"; break;
          case ak_error_curve_point        : p = "base point"; break;
          case ak_error_curve_point_order  : p = "base point order"; break;
          case ak_error_curve_prime_size   : p = "prime modulo p"; break;
          default : p = "unexpected parameter";
        }
        //ak_wcurve_paramset_to_log( wc );
        ak_error_message_fmt( reason, __func__ , "curve %s (OID: %s) has wrong %s",
                                                             oid->name.data, oid->id.data, p );
        result = ak_false;
        goto lab_exit;
      } else
          if( audit > ak_log_standard ) {
            ak_error_message_fmt( ak_error_ok, __func__ , "curve %s (OID: %s) is Ok",
                                                                oid->name.data, oid->id.data );
          }
    }
    handle = ak_oid_findnext_by_engine( handle, identifier );
  }

 lab_exit:
  if( !result ) ak_error_message( ak_error_get_value(), __func__ ,
                                                         "incorrect testing Weierstrass curves" );
   else if( audit >= ak_log_maximum ) ak_error_message( ak_error_get_value(), __func__ ,
                                                "testing Weierstrass curves ended successfully" );
 return result;
}




/* ----------------------------------------------------------------------------------------------- */
/*          реализация операций с точками эллиптической кривой в короткой форме Вейерштрасса       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wpoint_static_set( ak_wpoint_static wp, ak_wcurve_static wc )
{
  if( wp == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                                   "using null pointer to elliptic curve point" );
  if( wc == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                                         "using null pointer to elliptic curve" );
 /* копируем данные */
  memcpy( wp->x, wc->px, ak_mpzn512_size );
  memcpy( wp->y, wc->py, ak_mpzn512_size );
  ak_mpzn_set_ui( wp->y, ak_mpzn512_size, 1 );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для заданной точки \f$ P = (x:y:z) \f$ функция проверяет,
    что точка принадлежит эллиптической кривой, то есть что выполнено сравнение
    \f$ yz^2 \equiv x^3 + axz^2 + bz^3 \pmod{p}\f$.

    @param wp точка \f$ P \f$ эллиптической кривой
    @param ec эллиптическая кривая, на принадлежность которой проверяется точка \f$P\f$.

    @return Функция возвращает \ref ak_true если все проверки выполнены. В противном случае
    возвращается \ref ak_false.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_wpoint_static_is_ok( ak_wpoint_static wp, ak_wcurve_static ec )
{
  ak_mpznmax t, s;

 /* Проверяем принадлежность точки заданной кривой */
  ak_mpzn_set( t, ec->a, ec->size );
  ak_mpzn_mul_montgomery( t, t, wp->x, ec->p, ec->n, ec->size );
  ak_mpzn_set( s, ec->b, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->z, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( t, t, s, ec->p, ec->size ); // теперь в t величина (ax+bz)

  ak_mpzn_set( s, wp->z, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( t, t, s, ec->p, ec->n, ec->size ); // теперь в t величина (ax+bz)z^2

  ak_mpzn_set( s, wp->x, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->x, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( t, t, s, ec->p, ec->size ); // теперь в t величина x^3 + (ax+bz)z^2

  ak_mpzn_set( s, wp->y, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->z, ec->p, ec->n, ec->size ); // теперь в s величина x^3 + (ax+bz)z^2

  char *str;
  printf("s = %s\n", str = ak_ptr_to_hexstr( s, ec->size*sizeof( ak_uint64 ), ak_false )); free( str );
  printf("t = %s\n", str = ak_ptr_to_hexstr( t, ec->size*sizeof( ak_uint64 ), ak_false )); free( str );


  if( ak_mpzn_cmp( t, s, ec->size )) return ak_false;
 return ak_true;
}






























/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct wcurve в соответствии со значениями,
    хранящимися в структуре struct wcurve_params

    @param wc указатель на контекст кривой
    @param params указатель на параметры кривой
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_wcurve_create( ak_wcurve ec, ak_wcurve_paramset paramset )
{
  size_t bytelen = 0;
  int local_error = ak_error_ok;

  if( ec == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "use a null pointer to elliptic curve context" );
  if( paramset == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                              "use a null pointer to elliptic curve parameters" );
  bytelen = paramset->size*sizeof( ak_uint64 );
  ec->size = paramset->size;
  ec->n = paramset->cn;
  ec->d = paramset->cd;
  ec->a = ec->b = ec->p = ec->q = ec->r2 = NULL;

 /* инициализируем коэффициент a */
  if(( ec->a = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "wrong coefficient A memory allocation" );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->a, ec->size, paramset->ca )) != ak_error_ok ) {
    ak_error_message( local_error, __func__, "wrong coefficient A convertation" );
    goto wrong_label;
  }

 /* инициализируем коэффициент b */
  if(( ec->b = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__, "wrong coefficient B memory allocation" );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->b, ec->size, paramset->cb )) != ak_error_ok ) {
    ak_error_message( local_error, __func__, "wrong coefficient B convertation" );
    goto wrong_label;
  }

 /* инициализируем модуль p */
  if(( ec->p = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__, "wrong modulo P memory allocation" );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->p, ec->size, paramset->cp )) != ak_error_ok ) {
    ak_error_message( local_error, __func__, "wrong modulo P convertation" );
    goto wrong_label;
  }

 /* инициализируем порядок q */
 /* поскольку порядок группы может быть больше, чем р, нам приходится выделять под него */
 /* дополнительное слово */
  if(( ec->q = malloc( sizeof(ak_uint64) + bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__, "wrong order Q memory allocation" );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->q, 1+ec->size, paramset->cq )) != ak_error_ok ) {
    ak_error_message( local_error, __func__, "wrong order Q convertation" );
    goto wrong_label;
  }

 /* инициализируем константу r2 */
  if(( ec->r2 = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__, "wrong constant R2 memory allocation" );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->r2, ec->size, paramset->cr2 )) != ak_error_ok ) {
    ak_error_message( local_error, __func__, "wrong constant R2 convertation" );
    goto wrong_label;
  }

 /* предвычисление констант (переводим а, b в представление Монтгомери */
  ak_mpzn_mul_montgomery( ec->a, ec->a, ec->r2, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( ec->b, ec->b, ec->r2, ec->p, ec->n, ec->size );

 /* завершение и очистка памяти */
 return ak_error_ok;
 wrong_label:
   local_error = ak_error_get_value();
   ak_wcurve_destroy( ec );
 return local_error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_wcurve_destroy( ak_wcurve ec )
{
  int destroy_error = ak_error_ok;
  if( ec == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                               "destroing null pointer to elliptic curve context" );
  ec->size = 0; ec->d = 0; ec->n = 0;
  if( ec->a != NULL ) free( ec->a );
   else ak_error_message( destroy_error = ak_error_undefined_value, __func__ ,
                                         "destroing null pointer to elliptic curve coefficient A" );
  if( ec->b != NULL ) free( ec->b );
   else ak_error_message( destroy_error = ak_error_undefined_value, __func__ ,
                                         "destroing null pointer to elliptic curve coefficient B" );
  if( ec->p != NULL ) free( ec->p );
   else ak_error_message( destroy_error = ak_error_undefined_value, __func__ ,
                                                "destroing null pointer to elliptic curve modulo" );
  if( ec->q != NULL ) free( ec->q );
   else ak_error_message( destroy_error = ak_error_undefined_value, __func__ ,
                                                 "destroing null pointer to elliptic curve order" );
  if( ec->r2 != NULL ) free( ec->r2 );
   else ak_error_message( destroy_error = ak_error_undefined_value, __func__ ,
                                           "destroing null pointer to elliptic curve constant R2" );
 return destroy_error;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_wcurve_delete( ak_pointer ec )
{
  if( ec != NULL ) {
    ak_wcurve_destroy( ec );
    free( ec );
  } else ak_error_message( ak_error_null_pointer, __func__,
                                             "deleting a null pointer to elliptic curve context" );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляерт величину \f$\Delta \equiv -16(4a^3 + 27b^2) \pmod{p} \f$, зависящую
    от параметров эллиптической кривой

    @param d Вычет, в который помещается вычисленное значение.
    @param ec Контекст эллиптической кривой, для которой вычисляется ее дискриминант               */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_set_wcurve_discriminant( ak_uint64 *d, ak_wcurve ec )
{
  ak_mpznmax s, one = ak_mpznmax_one;

 /* определяем константы 4 и 27 в представлении Монтгомери */
  ak_mpzn_set_ui( d, ec->size, 4 );
  ak_mpzn_set_ui( s, ak_mpznmax_size, 27 );
  ak_mpzn_mul_montgomery( d, d, ec->r2, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->r2, ec->p, ec->n, ec->size );

 /* вычисляем 4a^3 (mod p) значение в представлении Монтгомери */
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );

 /* вычисляем значение 4a^3 + 27b^2 (mod p) в представлении Монтгомери */
  ak_mpzn_mul_montgomery( s, s, ec->b, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->b, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( d, d, s, ec->p, ec->size );

 /* определяем константу -16 в представлении Монтгомери и вычисляем D = -16(4a^3+27b^2) (mod p) */
  ak_mpzn_set_ui( s, ec->size, 16 );
  ak_mpzn_sub( s, ec->p, s, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->r2, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, s, ec->p, ec->n, ec->size );

 /* возвращаем результат (в обычном представлении) */
  ak_mpzn_mul_montgomery( d, d, one, ec->p, ec->n, ec->size );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_wcurve_discriminant_is_ok( ak_wcurve ec )
{
  ak_mpznmax d;
  if( ec == NULL ) { ak_error_message( ak_error_null_pointer, __func__ ,
                                               "using a null pointer to elliptic curve context" );
    return ak_false;
  }
  ak_mpzn_set_wcurve_discriminant( d, ec );
 return !ak_mpzn_cmp_ui( d, ec->size, 0 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает на вход контекст структуры wcurve_paramset и выполняет следующие проверки

     - проверяется, что параметры кривой заданы в виде допустимой последовательности
       шестнадцатеричных цифр,
     - проверяется, что модуль кривой (простое число \f$ p \f$) удовлетворяет неравенству
       \f$ 2^{n-32} < p < 2^n \f$, где \f$ n \f$ это либо 256, либо 512 в зависимости от
       параметров кривой,
     - проверяется, что дискриминант кривой отличен от нуля по модулю \f$ p \f$,
     - проверяется, что точка кривой, содержащаяся в структуре wcurve_paramset, действительно
       принадлежит эллиптической кривой,
     - проверяется, что порядок точки кривой равен простому числу \f$ q \f$,
       содержащемуся в структуре wcurve_paramset.

     @param ecp контекст структуры wcurve_paramset, содержащий в себе значения параметров
     эллиптической кривой. Значения контекстов, которые могут быть использованы библиотекой,
     задаются в файле \ref ak_parameters.h


     @return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае,
     возвращается код ошибки.                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wcurve_paramset_is_ok( const ak_wcurve_paramset ecp )
{
  struct wcurve ec;
  struct wpoint wp;
  int error = ak_error_ok;

 /* создали кривую и проверяем ее параметры */
  if(( error = ak_wcurve_create( &ec, ecp )) != ak_error_ok ) return error;
  if( ec.p[ ec.size-1 ] < 0x100000000LL ) { /* слишком маленький модуль */
    error = ak_error_curve_prime_size;
    goto ex2;
  }
  if( !ak_wcurve_discriminant_is_ok( &ec )) { /* нулевой дискриминант */
    error = ak_error_curve_discriminant;
    goto ex2;
  }
 /* теперь тестируем точку на кривой */
  if(( error = ak_wpoint_create( &wp, ecp )) != ak_error_ok ) goto ex2;
  if( ak_wpoint_is_ok( &wp, &ec ) != ak_true ) { /* точка не принадлежит кривой */
    error = ak_error_curve_point;
    goto ex1;
  }
  if( ak_wpoint_check_order( &wp, &ec ) != ak_true ) {
    error = ak_error_curve_point_order; /* порядок точки отличен от заданного */
    goto ex1;
  }

 /* удаляем контексты */
  ex1: ak_wpoint_destroy( &wp );
  ex2: ak_wcurve_destroy( &ec );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*          реализация операций с точками эллиптической кривой в короткой форме Вейерштрасса       */
/* ----------------------------------------------------------------------------------------------- */
/*!  Функция создает вектор \f$ (P_x:P_y:r^{-1}) \f$, являющийся точкой проективного пространства,
     соответствующего аффинной точке \f$ P=(P_x,P_y)\f$. Дополнительно, для оптимизации вычислений,
     точка записывается в представлении Монтгомери.

     @param wp указатель на структуру struct wpoint
     @param params Параметры эллиптической кривой, заданные в читаемой человеком форме.
     @return В случае возникновения ошибки, возвращается ее код. В противном случае,
     возвращается \ref ak_error_ok.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wpoint_create( ak_wpoint wp, ak_wcurve_paramset params )
{
 int local_error = ak_error_ok;
 size_t bytelen = 0;
 if( wp == NULL ) {
     ak_error_message( ak_error_null_pointer, __func__ ,
                                         "use a null pointer to point of elliptic curve context" );
     return ak_error_null_pointer;
 }
 if( params == NULL ) {
     ak_error_message( ak_error_null_pointer, __func__ ,
                                               "use a null pointer to elliptic curve parameters" );
     return ak_error_null_pointer;
 }

/* определяем размер координат точки в байтах */
 bytelen = params->size*sizeof( ak_uint64 );

/* инициализируем координату x */
 if(( wp->x = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, __func__ , "wrong coordinate X memory allocation" );
   goto wrong_label;
 }
 if(( local_error = ak_mpzn_set_hexstr( wp->x, params->size, params->cpx )) != ak_error_ok ) {
   ak_error_message( local_error, __func__ , "wrong coordinate X convertation" );
   goto wrong_label;
 }
/* инициализируем координату y */
 if(( wp->y = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, __func__ , "wrong coordinate Y memory allocation" );
   goto wrong_label;
 }
 if(( local_error = ak_mpzn_set_hexstr( wp->y, params->size, params->cpy )) != ak_error_ok ) {
   ak_error_message( local_error, __func__ , "wrong coordinate Y convertation" );
   goto wrong_label;
 }
/* инициализируем координату z */
 if(( wp->z = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, __func__ , "wrong coordinate Z memory allocation" );
   goto wrong_label;
 }
 ak_mpzn_set_ui( wp->z, params->size, 1 );

/* завершение и очистка памяти */
 return ak_error_ok;
 wrong_label:
   local_error = ak_error_get_value();
   ak_wpoint_destroy( wp );
 return local_error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст значением \f$(0:1:0) \f$ -- значениепм бесконечно
    удаленной точки эллиптической кривой

     @param wp указатель на структуру struct wpoint
     @param size Размер координат точки в словах (значение константы \ref ak_mpzn256_size или
     \ref ak_mpzn512_size )
     @return В случае возникновения ошибки, возвращается ее код. В противном случае,
     возвращается \ref ak_error_ok.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wpoint_create_as_unit( ak_wpoint wp, const size_t size )
{
 int local_error = ak_error_ok;
 size_t bytelen = 0;
 if( wp == NULL ) { ak_error_message( ak_error_null_pointer, __func__ ,
                                         "use a null pointer to point of elliptic curve context" );
     return ak_error_null_pointer;
 }
 if( size == 0 ) { ak_error_message( ak_error_zero_length, __func__ ,
                                                   "use a zero length of elliptic curve's point" );
     return ak_error_zero_length;
 }

/* определяем размер координат точки в байтах */
 bytelen = size*sizeof( ak_uint64 );

/* инициализируем координату x */
 if(( wp->x = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, __func__ , "wrong coordinate X memory allocation" );
   goto wrong_label;
 }
 ak_mpzn_set_ui( wp->x, size, 0 );
/* инициализируем координату y */
 if(( wp->y = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, __func__ , "wrong coordinate Y memory allocation" );
   goto wrong_label;
 }
 ak_mpzn_set_ui( wp->y, size, 1 );
/* инициализируем координату z */
 if(( wp->z = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, __func__, "wrong coordinate Z memory allocation" );
   goto wrong_label;
 }
 ak_mpzn_set_ui( wp->z, size, 0 );

/* завершение и очистка памяти */
 return ak_error_ok;
 wrong_label:
   local_error = ak_error_get_value();
   ak_wpoint_destroy( wp );
 return local_error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_wpoint_destroy( ak_wpoint wp )
{
  int destroy_error = ak_error_ok;
  if( wp == NULL ) { ak_error_message( ak_error_null_pointer, __func__ ,
                                   "destroing null pointer to point of elliptic curve context" );
    return ak_error_null_pointer;
  }
  if( wp->x != NULL ) free( wp->x );
    else ak_error_message( destroy_error = ak_error_undefined_value, __func__ ,
                           "destroing null pointer to coordinate X of elliptic curve's poiont" );
  if( wp->y != NULL ) free( wp->y );
    else ak_error_message( destroy_error = ak_error_undefined_value, __func__ ,
                           "destroing null pointer to coordinate Y of elliptic curve's poiont ");
  if( wp->z != NULL ) free( wp->z );
    else ak_error_message( destroy_error = ak_error_undefined_value, __func__ ,
                          "destroing null pointer to coordinate Z of elliptic curve's poiont " );
 return destroy_error;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_wpoint_delete( ak_pointer wp )
{
  if( wp != NULL ) {
    ak_wpoint_destroy( wp );
    free( wp );
  } else ak_error_message( ak_error_null_pointer, __func__ ,
                              "deleting a null pointer to point of elliptic curve context" );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для заданной точки \f$ P = (x:y:z) \f$ функция проверяет,
    что точка принадлежит эллиптической кривой, то есть выполнено сравнение
    \f$ yz^2 \equiv x^3 + axz^2 + bz^3 \pmod{p}\f$.

    @param wp точка \f$ P \f$ эллиптической кривой
    @param ec эллиптическая кривая, на принадлежность которой проверяется точка \f$P\f$.

    @return Функция возвращает \ref ak_true если все проверки выполнены. В противном случае
    возвращается \ref ak_false.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_wpoint_is_ok( ak_wpoint wp, ak_wcurve ec )
{
  ak_mpznmax t, s;

 /* Проверяем принадлежность точки заданной кривой */
  ak_mpzn_set( t, ec->a, ec->size );
  ak_mpzn_mul_montgomery( t, t, wp->x, ec->p, ec->n, ec->size );
  ak_mpzn_set( s, ec->b, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->z, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( t, t, s, ec->p, ec->size ); // теперь в t величина (ax+bz)

  ak_mpzn_set( s, wp->z, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( t, t, s, ec->p, ec->n, ec->size ); // теперь в t величина (ax+bz)z^2

  ak_mpzn_set( s, wp->x, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->x, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( t, t, s, ec->p, ec->size ); // теперь в t величина x^3 + (ax+bz)z^2

  ak_mpzn_set( s, wp->y, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->z, ec->p, ec->n, ec->size ); // теперь в s величина x^3 + (ax+bz)z^2

  if( ak_mpzn_cmp( t, s, ec->size )) return ak_false;
 return ak_true;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Для заданной точки \f$ P = (x:y:z) \f$ функция проверяет
    что порядок точки действительно есть величина \f$ q \f$, заданная в параметрах
    эллиптической кривой, то есть проверяется выполнимость равенства \f$ [q]P = \mathcal O\f$,
    где \f$ \mathcal O \f$ - бесконечно удаленная точка (ноль группы точек эллиптической кривой),
    а \f$ q \f$ порядок подгруппы, в которой реализуются вычисления.

    @param wp точка \f$ P \f$ эллиптической кривой
    @param ec эллиптическая кривая, на принадлежность которой проверяется точка \f$P\f$.

    @return Функция возвращает \ref ak_true если все проверки выполнены. В противном случае
    возвращается \ref ak_false.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_wpoint_check_order( ak_wpoint wp, ak_wcurve ec )
{
  ak_bool result = ak_false;
  struct wpoint ep;

  ak_wpoint_create_as_unit( &ep, ec->size );
  ak_wpoint_pow( &ep, wp, ec->q, 1+ec->size, ec );
  result = ak_mpzn_cmp_ui( ep.z, ec->size, 0 );
  ak_wpoint_destroy( &ep );

  return result;
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_wpoint_set( ak_wpoint left, ak_wpoint right, const size_t size )
{
  ak_mpzn_set( left->x, right->x, size );
  ak_mpzn_set( left->y, right->y, size );
  ak_mpzn_set( left->z, right->z, size );
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_wpoint_set_as_unit( ak_wpoint wp, const size_t size )
{
  ak_mpzn_set_ui( wp->x, size, 0 );
  ak_mpzn_set_ui( wp->y, size, 1 );
  ak_mpzn_set_ui( wp->z, size, 0 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Точка эллиптической кривой \f$ P = (x:y:z) \f$ заменяется значением \f$ 2P  = (x_3:y_3:z_3)\f$.
    При вычислениях используются соотношения, основанные на результатах работы
    D.Bernstein, T.Lange, <a href="http://eprint.iacr.org/2007/286">Faster addition and doubling
     on elliptic curves</a>, 2007.

    \code
      XX = X^2
      ZZ = Z^2
      w = a*ZZ+3*XX
      s = 2*Y*Z
      ss = s^2
      sss = s*ss
      R = Y*s
      RR = R^2
      B = (X+R)^2-XX-RR
      h = w^2-2*B
      X3 = h*s
      Y3 = w*(B-h)-2*RR
      Z3 = sss
    \endcode
                                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 void ak_wpoint_double( ak_wpoint wp, ak_wcurve ec )
{
 ak_mpznmax u1, u2, u3, u4, u5, u6, u7;

 if( ak_mpzn_cmp_ui( wp->z, ec->size, 0 ) == ak_true ) return;
 if( ak_mpzn_cmp_ui( wp->y, ec->size, 0 ) == ak_true ) {
   ak_wpoint_set_as_unit( wp, ec->size );
   return;
 }
 // dbl-2007-bl
 ak_mpzn_mul_montgomery( u1, wp->x, wp->x, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( u2, wp->z, wp->z, ec->p, ec->n, ec->size );
 ak_mpzn_lshift_montgomery( u4, u1, ec->p, ec->size );
 ak_mpzn_add_montgomery( u4, u4, u1, ec->p, ec->size );
 ak_mpzn_mul_montgomery( u3, u2, ec->a, ec->p, ec->n, ec->size );
 ak_mpzn_add_montgomery( u3, u3, u4, ec->p, ec->size );  // u3 = az^2 + 3x^2
 ak_mpzn_mul_montgomery( u4, wp->y, wp->z, ec->p, ec->n, ec->size );
 ak_mpzn_lshift_montgomery( u4, u4, ec->p, ec->size );   // u4 = 2yz
 ak_mpzn_mul_montgomery( u5, wp->y, u4, ec->p, ec->n, ec->size ); // u5 = 2y^2z
 ak_mpzn_lshift_montgomery( u6, u5, ec->p, ec->size ); // u6 = 2u5
 ak_mpzn_mul_montgomery( u7, u6, wp->x, ec->p, ec->n, ec->size ); // u7 = 8xy^2z
 ak_mpzn_lshift_montgomery( u1, u7, ec->p, ec->size );
 ak_mpzn_sub( u1, ec->p, u1, ec->size );
 ak_mpzn_mul_montgomery( u2, u3, u3, ec->p, ec->n, ec->size );
 ak_mpzn_add_montgomery( u2, u2, u1, ec->p, ec->size );
 ak_mpzn_mul_montgomery( wp->x, u2, u4, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( u6, u6, u5, ec->p, ec->n, ec->size );
 ak_mpzn_sub( u6, ec->p, u6, ec->size );
 ak_mpzn_sub( u2, ec->p, u2, ec->size );
 ak_mpzn_add_montgomery( u2, u2, u7, ec->p, ec->size );
 ak_mpzn_mul_montgomery( wp->y, u2, u3, ec->p, ec->n, ec->size );
 ak_mpzn_add_montgomery( wp->y, wp->y, u6, ec->p, ec->size );
 ak_mpzn_mul_montgomery( wp->z, u4, u4, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( wp->z, wp->z, u4, ec->p, ec->n, ec->size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для двух заданных точек эллиптической кривой \f$ P = (x_1: y_1: z_1) \f$ и
    \f$ Q = (x_2:y_2:z_2)\f$ вычисляется сумма \f$ P+Q = (x_3:y_3:z_3)\f$,
    которая присваивается точке \f$ P\f$.

    Для вычислений используются соотношения,
    приведенные в работе H.Cohen, A.Miyaji and T.Ono
    <a href=http://link.springer.com/chapter/10.1007/3-540-49649-1_6>Efficient elliptic curve
    exponentiation using mixed coordinates</a>, 1998.

    \code
      Y1Z2 = Y1*Z2
      X1Z2 = X1*Z2
      Z1Z2 = Z1*Z2
      u = Y2*Z1-Y1Z2
      uu = u^2
      v = X2*Z1-X1Z2
      vv = v^2
      vvv = v*vv
      R = vv*X1Z2
      A = uu*Z1Z2-vvv-2*R
      X3 = v*A
      Y3 = u*(R-A)-vvv*Y1Z2
      Z3 = vvv*Z1Z2
    \endcode

    Если в качестве точки \f$ Q \f$ передается точка \f$ P \f$,
    то функция ak_wpoint_add() корректно обрабатывает такую ситуацию и вызывает функцию
    удвоения точки ak_wpoint_double().

    @param wp1 Точка \f$ P \f$, в которую помещается результат операции сложения; первое слагаемое
    @param wp2 Точка \f$ Q \f$, второе слагаемое
    @param ec Эллиптическая кривая, которой принадллежат складываемые точки                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_wpoint_add( ak_wpoint wp1, ak_wpoint wp2, ak_wcurve ec )
{
  ak_mpznmax u1, u2, u3, u4, u5, u6, u7;

  if( ak_mpzn_cmp_ui( wp2->z, ec->size, 0 ) == ak_true ) return;
  if( ak_mpzn_cmp_ui( wp1->z, ec->size, 0 ) == ak_true ) {
    ak_wpoint_set( wp1, wp2, ec->size );
    return;
  }
  // поскольку удвоение точки с помощью формул сложения дает бесконечно удаленную точку,
  // необходимо выполнить проверку
  ak_mpzn_mul_montgomery( u1, wp1->x, wp2->z, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u2, wp2->x, wp1->z, ec->p, ec->n, ec->size );
  if( ak_mpzn_cmp( u1, u2, ec->size ) == 0 ) { // случай совпадения х-координат точки
    ak_mpzn_mul_montgomery( u1, wp1->y, wp2->z, ec->p, ec->n, ec->size );
    ak_mpzn_mul_montgomery( u2, wp2->y, wp1->z, ec->p, ec->n, ec->size );
    if( ak_mpzn_cmp( u1, u2, ec->size ) == 0 ) // случай полного совпадения точек
      ak_wpoint_double( wp1, ec );
     else ak_wpoint_set_as_unit( wp1, ec->size );
    return;
  }

  //add-1998-cmo-2
  ak_mpzn_mul_montgomery( u1, wp1->x, wp2->z, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u2, wp1->y, wp2->z, ec->p, ec->n, ec->size );
  ak_mpzn_sub( u2, ec->p, u2, ec->size );
  ak_mpzn_mul_montgomery( u3, wp1->z, wp2->z, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u4, wp2->y, wp1->z, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( u4, u4, u2, ec->p, ec->size );
  ak_mpzn_mul_montgomery( u5, u4, u4, ec->p, ec->n, ec->size );
  ak_mpzn_sub( u7, ec->p, u1, ec->size );
  ak_mpzn_mul_montgomery( wp1->x, wp2->x, wp1->z, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( wp1->x, wp1->x, u7, ec->p, ec->size );
  ak_mpzn_mul_montgomery( u7, wp1->x, wp1->x, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u6, u7, wp1->x, ec->p, ec->n, ec->size);
  ak_mpzn_mul_montgomery( u1, u7, u1, ec->p, ec->n, ec->size );
  ak_mpzn_lshift_montgomery( u7, u1, ec->p, ec->size );
  ak_mpzn_add_montgomery( u7, u7, u6, ec->p, ec->size );
  ak_mpzn_sub( u7, ec->p, u7, ec->size );
  ak_mpzn_mul_montgomery( u5, u5, u3, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( u5, u5, u7, ec->p, ec->size );
  ak_mpzn_mul_montgomery( wp1->x, wp1->x, u5, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u2, u2, u6, ec->p, ec->n, ec->size );
  ak_mpzn_sub( u5, ec->p, u5, ec->size );
  ak_mpzn_add_montgomery( u1, u1, u5, ec->p, ec->size );
  ak_mpzn_mul_montgomery( wp1->y, u4, u1, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( wp1->y, wp1->y, u2, ec->p, ec->size );
  ak_mpzn_mul_montgomery( wp1->z, u6, u3, ec->p, ec->n, ec->size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для точки \f$ P = (x:y:z) \f$ функция вычисляет аффинное представление,
    задаваемое следующим вектором \f$ P = \left( \frac{x}{z} \pmod{p}, \frac{y}{z} \pmod{p}, 1\right) \f$,
    где \f$ p \f$ модуль эллиптической кривой.

    @param wp Точка кривой, которая приводится к аффинной форме
    @param ec Эллиптическая кривая, которой принадлежит точка                                      */
/* ----------------------------------------------------------------------------------------------- */
 void ak_wpoint_reduce( ak_wpoint wp, ak_wcurve ec )
{
 ak_mpznmax u, one = ak_mpznmax_one;
 if( ak_mpzn_cmp_ui( wp->z, ec->size, 0 ) == ak_true ) {
   ak_wpoint_set_as_unit( wp, ec->size );
   return;
 }

 ak_mpzn_set_ui( u, ec->size, 2 );
 ak_mpzn_sub( u, ec->p, u, ec->size );
 ak_mpzn_modpow_montgomery( u, wp->z, u, ec->p, ec->n, ec->size ); // u <- z^{p-2} (mod p)
 ak_mpzn_mul_montgomery( u, u, one, ec->p, ec->n, ec->size );

 ak_mpzn_mul_montgomery( wp->x, wp->x, u, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( wp->y, wp->y, u, ec->p, ec->n, ec->size );
 ak_mpzn_set_ui( wp->z, ec->size, 1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для заданной точки \f$ P = (x:y:z) \f$ и заданного целого числа (вычета) \f$ k \f$
    функция вычисляет кратную точку \f$ Q \f$, удовлетворяющую
    равенству \f$  Q = [k]P = \underbrace{P+ \cdots + P}_{k\text{~раз}}\f$.

    Функция не приводит результирующую точку \f$ Q \f$ к аффинной форме.

    @param wq Точка \f$ Q \f$, в которую помещается результат
    @param wp Точка \f$ P \f$
    @param k Степень кратности
    @param size Размер степени \f$ k \f$ в машинных словах - значение, как правило,
    задаваемое константой \ref ak_mpzn256_size или \ref ak_mpzn512_size. В общем случае
    может приниимать любое неотрицательное значение.
    @param ec Эллиптическая кривая, на которой происходят вычисления                               */
/* ----------------------------------------------------------------------------------------------- */
 void ak_wpoint_pow( ak_wpoint wq, ak_wpoint wp, ak_uint64 *k, size_t size, ak_wcurve ec )
{
  ak_uint64 uk = 0;
  size_t s = size-1;
  long long int i, j;

  ak_wpoint_set_as_unit( wq, ec->size );
  while( k[s] == 0 ) {
     if( s > 0 ) --s;
      else return;
  }

  for( i = s; i >= 0; i-- ) {
     uk = k[i];
     for( j = 0; j < 64; j++ ) {
        ak_wpoint_double( wq, ec );
        if( uk&0x8000000000000000LL ) ak_wpoint_add( wq, wp, ec );
        uk <<= 1;
     }
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выводит в файл аудита значения параметров эллиптической кривой                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_wcurve_paramset_to_log( const ak_wcurve_paramset ecp )
{
  char message[160];

  ak_snprintf( message, 158, " a = %s", ecp->ca );
  ak_log_set_message( message );
  ak_snprintf( message, 158, " b = %s", ecp->cb );
  ak_log_set_message( message );
  ak_snprintf( message, 158, " p = %s", ecp->cp );
  ak_log_set_message( message );
  ak_snprintf( message, 158, " q = %s", ecp->cq );
  ak_log_set_message( message );
  ak_snprintf( message, 158, "px = %s", ecp->cpx );
  ak_log_set_message( message );
  ak_snprintf( message, 158, "py = %s", ecp->cpy );
  ak_log_set_message( message );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Проверяются все параметры эллиптических кривых, доступных через механизм OID.
    Проверка производится путем вызова функции ak_wcurve_paramset_is_ok().

    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения
    ошибки функция возвращает ak_false. Код ошибки можеть быть получен с помощью вызова
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_wcurve_test_paramset( void )
{
  ak_bool result = ak_true;
  ak_handle handle = ak_error_wrong_handle;
  int reason = ak_error_ok, audit = ak_log_get_level();

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing Weierstrass curves started" );

 /* организуем цикл по перебору всех известных библиотеке параметров эллиптических кривых */
  handle = ak_oid_find_by_engine( identifier );
  while( handle != ak_error_wrong_handle ) {
    if( ak_oid_get_mode( handle ) == wcurve_params ) {
      ak_oid oid = NULL;
      ak_wcurve_paramset wc = NULL;

      if(( oid = ak_handle_get_context( handle, oid_engine )) == NULL ) {
        ak_error_message( ak_error_get_value(), __func__, "internal error with wrong handle" );
        result = ak_false;
        goto lab_exit;
      }
      if(( wc = ( ak_wcurve_paramset ) oid->data ) == NULL )  {
        ak_error_message( ak_error_null_pointer, __func__,
                                      "internal error with null poionter to wcurve paramset" );
        result = ak_false;
        goto lab_exit;
      }
      if(( reason = ak_wcurve_paramset_is_ok( wc )) != ak_error_ok ) {
        char *p = NULL;
        switch( reason ) {
          case ak_error_curve_discriminant : p = "discriminant"; break;
          case ak_error_curve_point        : p = "base point"; break;
          case ak_error_curve_point_order  : p = "base point order"; break;
          case ak_error_curve_prime_size   : p = "prime modulo p"; break;
          default : p = "unexpected parameter";
        }
        ak_wcurve_paramset_to_log( wc );
        ak_error_message_fmt( reason, __func__ , "curve %s (OID: %s) has wrong %s",
                                                             oid->name.data, oid->id.data, p );
        result = ak_false;
        goto lab_exit;
      } else
          if( audit > ak_log_standard ) {
            ak_error_message_fmt( ak_error_ok, __func__ , "curve %s (OID: %s) is Ok",
                                                                oid->name.data, oid->id.data );
          }
    }
    handle = ak_oid_findnext_by_engine( handle, identifier );
  }

 lab_exit:
  if( !result ) ak_error_message( ak_error_get_value(), __func__ ,
                                                         "incorrect testing Weierstrass curves" );
   else if( audit >= ak_log_maximum ) ak_error_message( ak_error_get_value(), __func__ ,
                                                "testing Weierstrass curves ended successfully" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_curves.c  */
/* ----------------------------------------------------------------------------------------------- */
