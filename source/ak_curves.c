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
  ec->a = ec->b = ec->p = ec->q = ec->r1 = ec->r2 = NULL;

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
 /* инициализируем константу r1 */
  if(( ec->r1 = malloc( bytelen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong constant R1 memory allocation", __func__ );
    goto wrong_label;
  }
  if(( local_error = ak_mpzn_set_hexstr( ec->r1, ec->size, params->cr1 )) != ak_error_ok ) {
    ak_error_message( local_error, "wrong constant R1 convertation", __func__ );
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
  if( ec->r1 != NULL ) free( ec->r1 );
   else ak_error_message( destroy_error = ak_error_undefined_value,
                                 "destroing null pointer to elliptic curve constant R1", __func__ );
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
/*                                                                                    ak_curves.c  */
/* ----------------------------------------------------------------------------------------------- */
