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
  /* инициализируем коэффициент a */
  if((ec->a = ak_buffer_new_hexstr_str( params->ca, bytelen, ak_true )) == NULL ) {
    ak_error_message( local_error, "wrong coefficient A convertation", __func__ );
    goto wrong_label;
  }
  /* инициализируем коэффициент a */
  if((ec->b = ak_buffer_new_hexstr_str( params->cb, bytelen, ak_true )) == NULL ) {
    ak_error_message( local_error, "wrong coefficient B convertation", __func__ );
    goto wrong_label;
  }
  /* инициализируем модуль кривой */
  if((ec->p = ak_buffer_new_hexstr_str( params->cp, bytelen, ak_true )) == NULL ) {
    ak_error_message( local_error, "wrong prime P convertation", __func__ );
    goto wrong_label;
  }
  /* инициализируем порядок подгруппы группы точек эллиптической кривой */
  if((ec->q = ak_buffer_new_hexstr_str( params->cq, bytelen, ak_true )) == NULL ) {
    ak_error_message( local_error, "wrong subgroup order Q convertation", __func__ );
    goto wrong_label;
  }
  /* инициализируем вспомогательные переменные */
  if((ec->r2 = ak_buffer_new_hexstr_str( params->cr2, bytelen, ak_true )) == NULL ) {
    ak_error_message( local_error, "wrong additional variable R2 convertation", __func__ );
    goto wrong_label;
  }

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
  if( ec == NULL ) {
     ak_error_message( ak_error_null_pointer,
                                     "destroing null pointer to elliptic curve context", __func__ );
      return ak_error_null_pointer;
  }
  ec->size = ec->d = ec->n = 0;
  ec->a = ak_buffer_delete( ec->a );
   destroy_error = ak_error_get_value();
  ec->b = ak_buffer_delete( ec->a );
   destroy_error = ak_error_get_value();
  ec->p = ak_buffer_delete( ec->a );
   destroy_error = ak_error_get_value();
  ec->q = ak_buffer_delete( ec->a );
   destroy_error = ak_error_get_value();
  ec->r2 = ak_buffer_delete( ec->a );
   destroy_error = ak_error_get_value();

 return destroy_error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_curves.c  */
/* ----------------------------------------------------------------------------------------------- */
