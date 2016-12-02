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
/*   ak_curves.h                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_CURVES_H__
#define    __AK_CURVES_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mpzn.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для символьного описания параметров эллиптической кривой в форме Вейерштрасса */
/*! Структура определяет эллиптическую кривую, заданную в короткой форме Вейерштрасса, сравнением
    \f$ y^2 \equiv x^3 + ax + b \pmod{p} \f$, а также образующую точку \f$P=(x_P, y_P)\f$
    на этой кривой с заданным порядком \f$ q \f$.

    Порядок \f$ m \f$ всей группы точек эллиптической кривой может быть определен
    из равенства \f$ m = dq \f$, где величина \f$ d \f$ называется кофактором.

    Параметры \f$ n, r_1, r_2\f$ вводятся для оптимизации вычислений. Определим \f$ r = 2^{256}\f$
    или \f$ r=2^{512}\f$, тогда \f$ n \equiv n_1 \pmod{2^{64}}\f$, где \f$ n_1, r_1 \f$
    определяются равенством
    \f$r\cdot r_1 - n_1\cdot p = 1\f$ и \f$ r_2 \equiv r^2 \pmod{p}\f$.                            */
/* ----------------------------------------------------------------------------------------------- */
 struct wcurve_params {
 /*! \brief Количество слов в элементах конечного поля, может быть ak_mpzn256(512)_size */
  size_t size;
 /*! \brief Коэффициент \f$ a \f$ эллиптической кривой */
  const char *ca;
 /*! \brief Коэффициент \f$ b \f$ эллиптической кривой */
  const char *cb;
 /*! \brief Модуль \f$ p \f$ эллиптической кривой */
  const char *cp;
 /*! \brief Порядок \f$ q \f$ подгруппы, порождаемой образующей точкой \f$ P \f$ */
  const char *cq;
 /*! \brief x-координата образующей точки \f$ P = (x_P, y_P) \f$ */
  const char *cpx;
 /*! \brief y-координата образующей точки \f$ P = (x_P, y_P) \f$ */
  const char *cpy;
 /*! \brief Обратное значение степени двойки по модулю \f$p\f$ используемое в арифметике Монтгомери */
  const char *cr1;
 /*! \brief Удвоенная степень двойки по модулю \f$p\f$ используемая в арифметике Монтгомери */
  const char *cr2;
 /*! \brief Константа \f$ n \f$, используемая в арифметике Монтгомери */
  ak_uint64 cn;
 /*! \brief Кофактор порядка подгруппы, т.е. \f$ m = qd \f$, где \f$ m \f$ порядок всей группы */
  ak_uint64 cd;
};
 typedef struct wcurve_params *ak_wcurve_params;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий эллиптическую кривую, заданную в короткой форме Вейерштрасса

   Класс определяет эллиптическую кривую, заданную в короткой форме Вейерштрасса, сравнением
   \f$ y^2 \equiv x^3 + ax + b \pmod{p} \f$. Кроме того, класс содержит значение порядка\f$ q \f$
   подгруппы, в которой должны выполняться криптографические вычисления, кофактора \f$d\f$,
   а также значения констант \f$ n, r_1, r_2 \f$, которые используются при реализации арифметики в
   представлении Монтгомери. Определим \f$ r = 2^{256}\f$
   или \f$ r=2^{512}\f$, тогда \f$ n \equiv n_1 \pmod{2^{64}}\f$, где \f$ n_1, r_1 \f$
   определяются равенством
   \f$r\cdot r_1 - n_1\cdot p = 1\f$ и \f$ r_2 \equiv r^2 \pmod{p}\f$.                             */
/* ----------------------------------------------------------------------------------------------- */
 struct wcurve
{
 /*! \brief Количество слов в элементах конечного поля, может быть ak_mpzn256(512)_size */
  size_t size;
 /*! \brief Коэффициент \f$ a \f$ эллиптической кривой */
  ak_uint64 *a;
 /*! \brief Коэффициент \f$ b \f$ эллиптической кривой */
  ak_uint64 *b;
 /*! \brief Модуль \f$ p \f$ эллиптической кривой */
  ak_uint64 *p;
 /*! \brief Порядок \f$ q \f$ подгруппы, порождаемой образующей точкой \f$ P \f$ */
  ak_uint64 *q;
 /*! \brief Обратное значение степени двойки по модулю \f$p\f$ используемое в арифметике Монтгомери */
  ak_uint64 *r1;
 /*! \brief Удвоенная степень двойки по модулю \f$p\f$ используемая в арифметике Монтгомери */
  ak_uint64 *r2;
 /*! \brief Константа \f$ n \f$, используемая в арифметике Монтгомери */
  ak_uint64 n;
 /*! \brief Кофактор порядка подгруппы, т.е. \f$ m = qd \f$, где \f$ m \f$ порядок всей группы */
  ak_uint64 d;
};
/*! Контекст эллиптической кривой в короткой форме Вейерштрасса */
 typedef struct wcurve *ak_wcurve;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста эллиптической кривой в короткой форме Вейерштрасса */
 int ak_wcurve_create( ak_wcurve , ak_wcurve_params );
/*! \brief Создание указателя на контекст эллиптической кривой */
 ak_wcurve ak_wcurve_new( ak_wcurve_params );
/*! \brief Уничтожение данных из контекста эллиптической кривой */
 int ak_wcurve_destroy( ak_wcurve );
/*! \brief Уничтожение контекста эллиптической кривой */
 ak_pointer ak_wcurve_delete( ak_pointer );

/*! \brief Вычисление величины \f$ 4a^3 + 27b^2 \f$ для параметров кривой в форме Вейерштрасса */
 void ak_mpzn_set_wcurve_discriminant( ak_uint64 *, ak_wcurve );
/*! \brief Проверка корректности параметров эллиптической кривой, заданной в форме Вейерштрасса */
 ak_bool ak_wcurve_is_ok( ak_wcurve );
 
#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_curves.h  */
/* ----------------------------------------------------------------------------------------------- */

