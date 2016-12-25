/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2008-2016 by Axel Kenzo, axelkenzo@mail.ru                                      */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*   Redistribution and use in source and binary forms, with or without modification, are          */
/*   permitted provided that the following conditions are met:                                     */
/*                                                                                                 */
/*   1. Redistributions of source code must retain the above copyright notice, this list of        */
/*      conditions and the following disclaimer.                                                   */
/*   2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/*      conditions and the following disclaimer in the documentation and/or other materials        */
/*      provided with the distribution.                                                            */
/*   3. Neither the name of the copyright holder nor the names of its contributors may be used     */
/*      to endorse or promote products derived from this software without specific prior written   */
/*      permission.                                                                                */
/*                                                                                                 */
/*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/*   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/*   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL        */
/*   THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, */
/*   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/*   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/*   AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/*   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/*   OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/*                                                                                                 */
/*   ak_curves.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_curves.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct wcurve в соотвествии со значениями,
    хранящимися в структуре struct wcurve_params

    @param wc указатель на контекст кривой
    @param params указатель на параметры кривой
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_wcurve_create( ak_wcurve ec, ak_wcurve_params params )
{
  int local_error = ak_error_ok;
  size_t bytelen = 0;
  if( ec == NULL ) {
      ak_error_message( ak_error_null_pointer,
                                        "use a null pointer to elliptic curve context", __func__ );
      return ak_error_null_pointer;
  }
  if( params == NULL ) {
      ak_error_message( ak_error_null_pointer,
                                     "use a null pointer to elliptic curve parameters", __func__ );
      return ak_error_null_pointer;
  }

  bytelen = params->size*sizeof( ak_uint64 );
  ec->size = params->size;
  ec->n = params->cn;
  ec->d = params->cd;
  ec->a = ec->b = ec->p = ec->q = ec->r2 = NULL;

 /* инициализируем коэффициент a */
  if(( ec->a = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong coefficient A memory allocation", __func__ );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->a, ec->size, params->ca )) != ak_error_ok ) {
    ak_error_message( local_error, "wrong coefficient A convertation", __func__ );
    goto wrong_label;
  }

 /* инициализируем коэффициент b */
  if(( ec->b = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong coefficient B memory allocation", __func__ );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->b, ec->size, params->cb )) != ak_error_ok ) {
    ak_error_message( local_error, "wrong coefficient B convertation", __func__ );
    goto wrong_label;
  }
 /* инициализируем модуль p */
  if(( ec->p = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong modulo P memory allocation", __func__ );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->p, ec->size, params->cp )) != ak_error_ok ) {
    ak_error_message( local_error, "wrong modulo P convertation", __func__ );
    goto wrong_label;
  }
 /* инициализируем порядок q */
  if(( ec->q = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong order Q memory allocation", __func__ );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->q, ec->size, params->cq )) != ak_error_ok ) {
    ak_error_message( local_error, "wrong order Q convertation", __func__ );
    goto wrong_label;
  }
 /* инициализируем константу r2 */
  if(( ec->r2 = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong constant R2 memory allocation", __func__ );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->r2, ec->size, params->cr2 )) != ak_error_ok ) {
    ak_error_message( local_error, "wrong constant R2 convertation", __func__ );
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
 ak_wcurve ak_wcurve_new( ak_wcurve_params params )
{
  ak_wcurve ec = ( ak_wcurve ) malloc( sizeof( struct wcurve ));
  if( ec != NULL ) ak_wcurve_create( ec, params );
   else ak_error_message( ak_error_out_of_memory, "incorrect memory allocation", __func__ );
  return ec;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_wcurve_destroy( ak_wcurve ec )
{
  int destroy_error = ak_error_ok;
  if( ec == NULL ) { ak_error_message( ak_error_null_pointer,
                                     "destroing null pointer to elliptic curve context", __func__ );
    return ak_error_null_pointer;
  }
  ec->size = ec->d = ec->n = 0;
  if( ec->a != NULL ) free( ec->a );
   else ak_error_message( destroy_error = ak_error_undefined_value,
                               "destroing null pointer to elliptic curve coefficient A", __func__ );
  if( ec->b != NULL ) free( ec->b );
   else ak_error_message( destroy_error = ak_error_undefined_value,
                               "destroing null pointer to elliptic curve coefficient B", __func__ );
  if( ec->p != NULL ) free( ec->p );
   else ak_error_message( destroy_error = ak_error_undefined_value,
                                      "destroing null pointer to elliptic curve modulo", __func__ );
  if( ec->q != NULL ) free( ec->q );
   else ak_error_message( destroy_error = ak_error_undefined_value,
                                       "destroing null pointer to elliptic curve order", __func__ );
  if( ec->r2 != NULL ) free( ec->r2 );
   else ak_error_message( destroy_error = ak_error_undefined_value,
                                 "destroing null pointer to elliptic curve constant R2", __func__ );
 return destroy_error;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_wcurve_delete( ak_pointer ec )
{
  if( ec != NULL ) {
    ak_wcurve_destroy( ec );
    free( ec );
  } else ak_error_message( ak_error_null_pointer,
                                  "deleting a null pointer to elliptic curve context", __func__ );
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
 ak_bool ak_wcurve_is_ok( ak_wcurve ec )
{
  ak_mpznmax d;

  if( ec == NULL ) {
    ak_error_message( ak_error_null_pointer,
                                "using a null pointer to elliptic curve context", __func__ );
    return ak_false;
  }
  ak_mpzn_set_wcurve_discriminant( d, ec );
 return !ak_mpzn_cmp_ui( d, ec->size, 0 );
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
 int ak_wpoint_create( ak_wpoint wp, ak_wcurve_params params )
{
 int local_error = ak_error_ok;
 size_t bytelen = 0;
 if( wp == NULL ) {
     ak_error_message( ak_error_null_pointer,
                             "use a null pointer to point of elliptic curve context", __func__ );
     return ak_error_null_pointer;
 }
 if( params == NULL ) {
     ak_error_message( ak_error_null_pointer,
                                    "use a null pointer to elliptic curve parameters", __func__ );
     return ak_error_null_pointer;
 }

/* определяем размер координат точки в байтах */
 bytelen = params->size*sizeof( ak_uint64 );

/* инициализируем координату x */
 if(( wp->x = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, "wrong coordinate X memory allocation", __func__ );
   goto wrong_label;
 }
 if(( local_error = ak_mpzn_set_hexstr( wp->x, params->size, params->cpx )) != ak_error_ok ) {
   ak_error_message( local_error, "wrong coordinate X convertation", __func__ );
   goto wrong_label;
 }
/* инициализируем координату y */
 if(( wp->y = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, "wrong coordinate Y memory allocation", __func__ );
   goto wrong_label;
 }
 if(( local_error = ak_mpzn_set_hexstr( wp->y, params->size, params->cpy )) != ak_error_ok ) {
   ak_error_message( local_error, "wrong coordinate Y convertation", __func__ );
   goto wrong_label;
 }
/* инициализируем координату z */
 if(( wp->z = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, "wrong coordinate Z memory allocation", __func__ );
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
 if( wp == NULL ) { ak_error_message( ak_error_null_pointer,
                             "use a null pointer to point of elliptic curve context", __func__ );
     return ak_error_null_pointer;
 }
 if( size == 0 ) { ak_error_message( ak_error_zero_length,
                                       "use a zero length of elliptic curve's point", __func__ );
     return ak_error_zero_length;
 }

/* определяем размер координат точки в байтах */
 bytelen = size*sizeof( ak_uint64 );

/* инициализируем координату x */
 if(( wp->x = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, "wrong coordinate X memory allocation", __func__ );
   goto wrong_label;
 }
 ak_mpzn_set_ui( wp->x, size, 0 );
/* инициализируем координату y */
 if(( wp->y = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, "wrong coordinate Y memory allocation", __func__ );
   goto wrong_label;
 }
 ak_mpzn_set_ui( wp->y, size, 1 );
/* инициализируем координату z */
 if(( wp->z = malloc( bytelen )) == NULL ) {
   ak_error_message( ak_error_out_of_memory, "wrong coordinate Z memory allocation", __func__ );
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
  if( wp == NULL ) { ak_error_message( ak_error_null_pointer,
                          "destroing null pointer to point of elliptic curve context", __func__ );
    return ak_error_null_pointer;
  }
  if( wp->x != NULL ) free( wp->x );
    else ak_error_message( destroy_error = ak_error_undefined_value,
                "destroing null pointer to coordinate X of elliptic curve's poiont ", __func__ );
  if( wp->y != NULL ) free( wp->y );
    else ak_error_message( destroy_error = ak_error_undefined_value,
                "destroing null pointer to coordinate Y of elliptic curve's poiont ", __func__ );
  if( wp->z != NULL ) free( wp->z );
    else ak_error_message( destroy_error = ak_error_undefined_value,
                "destroing null pointer to coordinate Z of elliptic curve's poiont ", __func__ );
    return destroy_error;

}

/* ----------------------------------------------------------------------------------------------- */
 ak_wpoint ak_wpoint_new( ak_wcurve_params params )
{
  ak_wpoint wp = ( ak_wpoint ) malloc( sizeof( struct wpoint ));
  if( wp != NULL ) ak_wpoint_create( wp, params );
   else ak_error_message( ak_error_out_of_memory, "incorrect memory allocation", __func__ );
  return wp;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_wpoint ak_wpoint_new_as_unit( const size_t size )
{
  ak_wpoint wp = ( ak_wpoint ) malloc( sizeof( struct wpoint ));
  if( wp != NULL ) ak_wpoint_create_as_unit( wp, size );
   else ak_error_message( ak_error_out_of_memory, "incorrect memory allocation", __func__ );
  return wp;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_wpoint_delete( ak_pointer wp )
{
  if( wp != NULL ) {
    ak_wpoint_destroy( wp );
    free( wp );
  } else ak_error_message( ak_error_null_pointer,
                         "deleting a null pointer to point of elliptic curve context", __func__ );
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
  return ak_false;
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
    то функция ak_wpoint_addd() корректно обрабатывает такую ситуацию и вызывает функцию
    удвоения точки ak_wpoint_double().

    @param wp1 Точка \f$ P \f$, в которую помещается результат операции сложения; первое слагаемое
    @param wp1 Точка \f$ Q \f$, второе слагаемое
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

 ak_mpzn_set_ui( u, ec->size, 2 );
 ak_mpzn_sub( u, ec->p, u, ec->size );
 ak_mpzn_modpow_montgomery( u, wp->z, u, ec->p, ec->n, ec->size ); // u <- z^{p-2} (mod p)
 ak_mpzn_mul_montgomery( u, u, one, ec->p, ec->n, ec->size );

 ak_mpzn_mul_montgomery( wp->x, wp->x, u, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( wp->y, wp->y, u, ec->p, ec->n, ec->size );
 ak_mpzn_set_ui( wp->z, ec->size, 1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_curves.c  */
/* ----------------------------------------------------------------------------------------------- */
