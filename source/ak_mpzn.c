/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2016 by Axel Kenzo, axelkenzo@mail.ru                                    */
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
/*   ak_mpzn.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mpzn.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_MULQ_GCC
 #define LIBAKRYPT_HAVE_ASM_CODE
 #define umul_ppmm(w1, w0, u, v) \
 __asm__ ("mulq %3" : "=a,a" (w0), "=d,d" (w1) : "%0,0" (u), "r,m" (v))
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifndef LIBAKRYPT_HAVE_ASM_CODE
 /* реализация метода Карацубы для двух 64-х битных чисел */
 #define umul_ppmm( w1, w0, u, v )                  \
 do {                                               \
    ak_uint64 __x0, __x1, __x2, __x3;               \
    ak_uint32 __ul, __vl, __uh, __vh;               \
    ak_uint64 __u = (u), __v = (v);                 \
                                                    \
    __ul = __u & 0xFFFFFFFF;                        \
    __uh = __u >> 32;                               \
    __vl = __v & 0xFFFFFFFF;                        \
    __vh = __v >> 32;                               \
                                                    \
    __x0 = (ak_uint64) __ul * __vl;					\
    __x1 = (ak_uint64) __ul * __vh;					\
    __x2 = (ak_uint64) __uh * __vl;					\
    __x3 = (ak_uint64) __uh * __vh;					\
                                                    \
    __x1 += ( __x0 >> 32 );                         \
    __x1 += __x2;                                   \
    if (__x1 < __x2) __x3 += ((ak_uint64)1 << 32 ); \
                                                    \
    (w1) = __x3 + (__x1 >> 32 );			        \
    (w0) = ( __x1 << 32 ) + ( __x0 & 0xFFFFFFFF );	\
 } while (0)
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает значение вычета x вычету z. Для оптимизацции вычислений проверка
    корректности входных данных не производится.

    @param z Вычет, которому присваивается значение
    @param x Вычет, значение которого присваивается.
    @param size Размер массива в словах типа \ref ak_uint64. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.                           */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_set( ak_uint64 *z, ak_uint64 *x, const size_t size )
{
  memcpy( z, x, size*sizeof (ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает указатель на массив как вычет одного из типов ak_mpznxxx и присваивает
    этому вычету беззнаковое целое значение value.

    @param x Вычет, в который помещается значение value
    @param size Размер массива в словах типа \ref ak_uint64. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.
    @param value Значение, которое присваивается вычету.

    @return В случае успеха, функция возвращает ноль (\ref ak_error_ok). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_set_ui( ak_uint64 *x, const size_t size, ak_uint64 value )
{
  memset( x, 0, size*sizeof( ak_uint64 ));
  x[0] = value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает указатель на массив как вычет одного из типов ak_mpznxxx и присваивает
    этому вычету случайное значение, вырабатываемое заданным генератором псевдо случайных чисел.

    @param x Указатель на массив, в который помещается значение вычета
    @param size Размер массива в словах типа \ref ak_uint64. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.
    @param generator Указатель на генератор псевдо случайных чисел,
    используемый для генерации случайного вычета.

    @return В случае успеха, функция возвращает ноль (\ref ak_error_ok). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_set_random( ak_uint64 *x, const size_t size, ak_random generator )
{
  if( x == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to mpzn" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using a zero legth of input data" );
    return ak_error_zero_length;
  }
  if( generator == NULL ) {
    ak_error_message( ak_error_undefined_value, __func__, "using an undefined random generator" );
    return ak_error_undefined_value;
  }
 return ak_random_ptr( generator, x, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_set_random_modulo( ak_uint64 *x, ak_uint64 *p,
                                                            const size_t size, ak_random generator )
{
  size_t midx = size-1;
  if( x == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to mpzn" );
    return ak_error_null_pointer;
  }
  if( p == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to modulo" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using a zero legth for generated data" );
    return ak_error_zero_length;
  }
  if( generator == NULL ) {
    ak_error_message( ak_error_undefined_value, __func__ , "using an undefined random generator" );
    return ak_error_undefined_value;
  }

  /* определяем старший значащий разряд у модуля */
  while( p[midx] == 0 ) {
    if( midx == 0 ) {
      ak_error_message( ak_error_undefined_value, __func__ , "modulo is equal to zero" );
      return ak_error_undefined_value;
    } else --midx;
  }

  /* старший разряд - по модулю, остальное мусор */
  memset( x, 0, size*sizeof( ak_uint64 ));
  x[midx] = ak_random_uint64( generator )%p[midx];
  if( midx > 0 ) ak_random_ptr( generator, x, midx*sizeof( ak_uint64));

 return ak_error_ok;
}
 
/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает указатель на массив как вычет одного из типов ak_mpznxxx и присваивает
    этому вычету значение, содержащееся в строке шестнадцатеричных вычетов.

    @param x Указатель на массив, в который помещается значение вычета
    @param size Размер массива в словах типа \ref ak_uint64. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.
    @param str Строка шестнадцатеричных символов,
    значение которой присваивается вычету. Если строка содержит больше символов, чем может
    поместиться в заданный массив, то возбуждаетс ошибка.

    @return В случае успеха, функция возвращает ноль (\ref ak_error_ok). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_set_hexstr( ak_uint64 *x, const size_t size, const char *str )
{
  if( x == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to mpzn" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using a zero legth of input data" );
    return ak_error_zero_length;
  }
  if( str == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to hexademal string" );
    return ak_error_null_pointer;
  }
 return ak_hexstr_to_ptr( str, x, size*sizeof( ak_uint64 ), ak_true );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает строку, в которую помещается шестнадцатеричное значение вычета. В последствии,
    созданная строка должна быть удалена пользователем самостоятельно с помощью вызова функции free().

    @param x[out] Указатель на массив, в который помещается значение вычета
    @param size[in] Размер массива в словах типа \ref ak_uint64. Данная переменная может
    принимать значения \ref ak_mpzn256_size, \ref ak_mpzn512_size и т.п.

    @return В случае успеха, функция указатель на созданную строку. В противном случае возвращается
    NULL. Код ошибки модет быть получен с помощью вызова функции ak_error_get_value().             */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_mpzn_to_hexstr( ak_uint64 *x, const size_t size )
{
  if( x == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to mpzn" );
    return NULL;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using a zero legth of input data" );
    return NULL;
  }
 return ak_ptr_to_hexstr( x, size*sizeof( ak_uint64 ), ak_true );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                  арифметические операции                                        */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию сложения двух вычетов кольца \f$ \mathbb Z_{2^n} \f$, то
    есть реализует операцию \f$ z \equiv x + y \pmod{2^n}\f$.
    В качестве результата функции возвращается знак переноса r, принимающий значение либо 0, либо 1.
    Знак переноса позволяет интерпретировать сложение вычетов как сложение целых чисел, то есть
    записать точное равенство \f$ x + y = z + r\cdot 2^n\f$.

    Допускается использовать в качестве аргумента z один из аргументов x или y.

    Для максимальной эффективности вычислений функция не проверяет допустимые значения параметров.

    @param z    Вычет, в который помещается результат
    @param x    Вычет (левое слагаемое)
    @param y    Вычет (правое слагаемое)
    @param size Размер вычетов в машинных словах - значение, задаваемое
    константой \ref ak_mpzn256_size или \ref ak_mpzn512_size
    @return Функция возвращает значение знака переноса.                                            */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_mpzn_add( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y, const size_t size )
{
  size_t i = 0;
  ak_uint64 av = 0, bv = 0, cy = 0;

  for( i = 0; i < size; i++ ) {
     av = x[i]; bv = y[i];
     bv += cy;
     cy = bv < cy;
     bv += av;
     cy += bv < av;
     z[i] = bv;
  }
  return cy;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию вычитания двух вычетов кольца \f$ \mathbb Z_{2^n} \f$, то
    есть реализует операцию \f$ z \equiv x - y \pmod{2^n}\f$.
    В качестве результата функции возвращается знак переноса r, принимающий значение либо 0, либо 1.
    Знак переноса позволяет интерпретировать операцию как вычитание целых чисел, то есть
    записать равенство \f$ z = x - y + r\cdot 2^n\f$.

    Допускается использовать в качестве аргумента z один из аргументов x или y.

    Для максимальной эффективности вычислений функция не проверяет допустимые значения параметров.

    @param z    Вычет, в который помещается результат
    @param x    Вычет, из которого происходит вычитание
    @param y    Вычитаемое
    @param size Размер вычетов в машинных словах - значение, задаваемое
    константой \ref ak_mpzn256_size или \ref ak_mpzn512_size
    @return Функция возвращает значение знака переноса.                                            */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_mpzn_sub( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y, const size_t size )
{
  size_t i = 0;
  ak_uint64 av = 0, bv = 0, cy = 0;

  for( i = 0; i < size; i++ ) {
     av = x[i]; //b = y[i];
     bv = av - cy;
     cy = bv > av;
     av = bv - y[i];
     cy += av > bv;
     z[i] = av;
  }
  return cy;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию сравнения (реализация операции сравнения основывается на
    операции вычитания вычетов).

    @param x    Левый аргумент операции сравнения
    @param y    Правый аргумент операции сравнения
    @param size Размер вычетов в машинных словах - значение, задаваемое
    константой \ref ak_mpzn256_size или \ref ak_mpzn512_size
    @return Функция возвращает 1, если левый аргумент больше чем правый, -1 если левый аргумент
            меньше, чем правый и 0 если оба аргумента функции совпадают.                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mpzn_cmp( ak_uint64 *x, ak_uint64 *y, const size_t size )
{
  size_t i = 0;
  ak_mpznmax z = ak_mpznmax_zero;
  ak_uint64 cy = ak_mpzn_sub( z, x, y, size );

  if( cy ) return -1;
  do{ if( z[i] ) return 1; } while( ++i < size );
  return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция сравнивает вычет x со значением value.  В случае равенства значений возвращается
   \ref ak_true. В противном случае, возвращается \ref ak_false.

   @param x Заданный вычет
   @param size Размер вычетов в машинных словах - значение, задаваемое константой
   \ref ak_mpzn256_size или \ref ak_mpzn512_size
   @param value Значение, с которым происходит сравнение.
   @return Функция возвращает \ref ak_true в случае равенства значений.
   В противном случае, возвращается \ref ak_false.                                                 */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_mpzn_cmp_ui( ak_uint64 *x, const size_t size, const ak_uint64 value )
{
  size_t i = 0;
  if( x[0] != value ) return ak_false;
  if( size > 1 )
    for( i = 1; i < size; i++ ) if( x[i] != 0 ) return ak_false;
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_mpzn_mul_ui( ak_uint64 *z, ak_uint64 *x, const size_t size, const ak_uint64 d )
{
  size_t j = 0;
  ak_uint64 m = 0;
  ak_mpznmax w = ak_mpznmax_zero;
  for( j = 0; j < size; j++ ) {
        ak_uint64 w1, w0, cy;
        umul_ppmm( w1, w0, d, x[j] );
        w[j] += m;
        cy = w[j] < m;

        w[j] += w0;
        cy += w[j] < w0;
        m = w1 + cy;
     }
 memcpy( z, w, sizeof( ak_uint64 )*size );
 return m;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух вычетов как двух целых чисел, то есть
    для \f$ x, y \in \mathbb Z_{2^n} \f$ вычисляется значение \f$ z \in \mathbb Z_{2^n} \f$
    для которого в точности выполнено равенство \f$ z = x\cdot y\f$.

    Допускается использовать в качестве аргумента z один из аргументов x или y.
    Однако надо обязательно учитывать тот факт, что результат z занимает в два раза
    больше места чем x или y.

    Для максимальной эффективности вычислений функция не проверяет допустимые значения параметров.

    @param z    Вычет, в который помещается результат. Должен иметь длину в два раза большую,
    чем длины вычетов x и y.
    @param x    Вычет (левый множитель)
    @param y    Вычет (равый множитель)
    @param size Размер вычетов x, y в машинных словах - значение, задаваемое константой
    \ref ak_mpzn256_size или \ref ak_mpzn512_size.
    @return Функция не возвращает значение.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_mul( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y, const size_t size )
{
 size_t i = 0, j = 0, ij = 0;
 ak_mpznmax w = ak_mpznmax_zero;

 for( i = 0; i < size; i++ ) {
    ak_uint64 m = 0, d = x[i];
    for( j = 0, ij = i; j < size; j++ , ij++ ) {
       ak_uint64 w1, w0, cy;
       umul_ppmm( w1, w0, d, y[j] );
       w[ij] += m;
       cy = w[ij] < m;

       w[ij] += w0;
       cy += w[ij] < w0;
       m = w1 + cy;
    }
    w[ij] = m;
 }
 memcpy( z, w, 2*sizeof( ak_uint64 )*size );
}

/* ----------------------------------------------------------------------------------------------- */
/* Операции Монтгомери:                                                                            */
/* реализованы операции сложения и умножения вычетов по материалам статьи                          */
/* C. Koc, T.Acar, B. Kaliski Analyzing and Comparing Montgomery Multiplication Algorithms         */
/*                                                             IEEE Micro, 16(3):26-33, June 1996. */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция складывает два вычета x и y по модулю p, после чего приводит полученную сумму
    по модулю p, то есть вычисляет значение сравнения \f$ z \equiv x + y \pmod{p}\f$.
    Результат помещается в переменную z. Указатель на z может совпадать с одним из указателей на
    слагаемые.

    @param z Указатель на вычет, в который помещается результат
    @param x Левый аргумент опреации сложения
    @param y Правый аргумент операции сложения
    @param p Модуль, по которому производяится операция сложения
    @param size Размер модуля в словах (значение константы ak_mpzn256_size или ak_mpzn512_size )   */
/* ----------------------------------------------------------------------------------------------- */
 inline void ak_mpzn_add_montgomery( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y,
                                                                ak_uint64 *p, const size_t size )
{
  size_t i = 0;
  ak_uint64 av = 0, bv = 0, cy = 0;
  ak_mpznmax t = ak_mpznmax_zero;

 // сначала складываем: (x + y) -> t
  for( i = 0; i < size; i++, x++, y++ ) {
     av = *x; bv = *y;
     bv += cy;
     cy = bv < cy;
     bv += av;
     cy += bv < av;
     t[i] = bv;
  }
  t[size] = cy; cy = 0;
 // потом вычитаем: (t - p) -> z
  for( i = 0; i < size; i++, p++ ) {
     av = t[i];
     bv = av - cy;
     cy = bv > av;
     av = bv - *p;
     cy += av > bv;
     z[i] = av;
  }
  if( t[size] != cy ) memcpy( z, t, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция умножает вычет x на 2, после чего приводит полученную сумму
    по модулю p, то есть вычисляет значение сравнения \f$ z \equiv 2x \pmod{p}\f$.
    Умножение производится путем сдвига на 1 разряд влево и последующего вычистания модуля p.

    Результат помещается в переменную z. Указатель на z может совпадать с одним из указателей на
    слагаемые.

    @param z Вычет, в который помещается результат
    @param x Вычет, для которого производится умножение
    @param y Правый аргумент операции сложения
    @param p Модуль, по которому производяится операция сложения
    @param size Размер модуля в словах (значение константы ak_mpzn256_size или ak_mpzn512_size )   */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_lshift_montgomery( ak_uint64 *z, ak_uint64 *x, ak_uint64 *p, const size_t size )
{
  size_t i;
  ak_uint64 av = 0, bv = 0, cy = 0;
  ak_mpznmax t = ak_mpznmax_zero;

  t[size] = 0;
  for( i = 0; i < size; i++, p++ ) {
    t[i+1] =  (( x[i]&0x8000000000000000LL ) > 0 );
    t[i] |= x[i] << 1; // сначала сдвигаем на один разряд влево
    av = t[i];         // потом вычитаем модуль
    bv = av - cy;
    cy = bv > av;
    av = bv - *p;
    cy += av > bv;
    z[i] = av;
   }
   if( t[size] != cy ) memcpy( z, t, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция умножает два вычета x и y в представлении Моонтгомери, после чего приводит полученное
    произведение по модулю p, то есть для \f$ x \equiv x_0r \pmod{p} \f$ и
    \f$ y \equiv y_0r \pmod{p} \f$ функция вычисляет значение,
    удовлетворяющее сравнению \f$ z \equiv x_0y_0r \pmod{p}\f$.
    Результат помещается в переменную z. Указатель на z может совпадать с одним из указателей на
    перемножаемые вычеты.

    @param z Указатель на вычет, в который помещается результат
    @param x Левый аргумент опреации сложения
    @param y Правый аргумент операции сложения
    @param p Модуль, по которому производятся вычисления
    @param n0 Константа, используемая в вычислениях. Представляет собой младшее слово числа n,
    удовлетворяющего равенству \f$ rs - np = 1\f$.
    @param size Размер модуля в словах (значение константы ak_mpzn256_size или ak_mpzn512_size )   */
/* ----------------------------------------------------------------------------------------------- */
 inline void ak_mpzn_mul_montgomery( ak_uint64 *z, ak_uint64 *x, ak_uint64 *y,
                                               ak_uint64 *p, ak_uint64 n0, const size_t size )
{
  size_t i = 0, j = 0, ij = 0;
  ak_uint64 av = 0, bv = 0, cy = 0;
  ak_mpznmax t = ak_mpznmax_zero;

  // ak_mpzn_mul( t, x, y, size );
  for( i = 0; i < size; i++ ) {
     ak_uint64 c = 0, m = x[i];
     for( j = 0, ij = i; j < size; j++ , ij++ ) {
        ak_uint64 w1, w0, cy;
        umul_ppmm( w1, w0, m, y[j] );
        t[ij] += c;
        cy = t[ij] < c;

        t[ij] += w0;
        cy += t[ij] < w0;
        c = w1 + cy;
     }
     t[ij] = c;
  }

  //  ak_mpzn_mul( u, t, n, size );
  //  ak_mpzn_mul( u, u, p, size );
  //  ak_mpzn_add( u, u, t, (size<<1));
  for( i = 0; i < size; i++ ) {
     ak_uint64 c = 0, m = t[i]*n0;
     for( j = 0, ij = i; j < size; j++ , ij++ ) {
        ak_uint64 w1, w0, cy;
        umul_ppmm( w1, w0, m, p[j] );
        t[ij] += c;
        cy = t[ij] < c;

        t[ij] += w0;
        cy += t[ij] < w0;
        c = w1;
        c += cy;
     }
     do {
         t[ij] += c;
         c = t[ij] < c;
         ij++;
     } while( c != 0 );
  }

  // вычитаем из результата модуль p
  for( i = 0, j = size; i < size; i++, j++ ) {
     av = t[j];
     bv = av - cy;
     cy = bv > av;
     av = bv - p[i];
     cy += av > bv;
     z[i] = av;
  }
  //if( cy == 1 ) memcpy( z, t+size, size*sizeof( ak_uint64 )); <--- это ошибочный вариант !!!
  if( cy != t[2*size] ) memcpy( z, t+size, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Пусть вычет x задан в представлении Монтгомери в виде \f$ xr \f$, где \f$ r \f$
    заданная степень двойки. Тогда, функция вычисляет вычет z,
    удовлетворяющий сравнению \f$z \equiv (x^k)r \pmod{p}\f$.
    Результат z является значением вычета \f$ x^k \pmod{p}\f$ в представлении Монтгомери.
    Величины k и p задаются как обычные вычеты, р отлично от нуля.

    @param z Вычет, в который помещается результат
    @param x Вычет, который возводится в степень k
    @param k Степень, в которую возводится вычет x
    @param p Модуль, по которому производятся вычисления
    @param n0 Константа, используемая в вычислениях. Представляет собой младшее слово числа n,
    удовлетворяющего равенству \f$ rs - np = 1\f$.
    @param size Размер модуля в словах (значение константы \ref ak_mpzn256_size
    или \ref ak_mpzn512_size )                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_modpow_montgomery( ak_uint64 *z, ak_uint64 *x, ak_uint64 *k,
                                                   ak_uint64 *p, ak_uint64 n0, const size_t size )
{
  ak_uint64 uk = 0;
  size_t s = size-1;
  long long int i, j;
  ak_mpznmax res = ak_mpznmax_zero; // это константа r (mod p) = r-p
  if( ak_mpzn_sub( res, res, p, size ) == 0 ) {
    ak_error_message( ak_error_undefined_value,
                                          "using an unexpected value of prime modulo", __func__ );
    return;
  }
  while( k[s] == 0 ) {
     if( s > 0 ) --s;
      else {
             ak_mpzn_set( z, res, size );
             return;
           }
  }
  for( i = s; i >= 0; i-- ) {
     uk = k[i];
     for( j = 0; j < 64; j++ ) {
        ak_mpzn_mul_montgomery( res, res, res, p, n0, size );
        if( uk&0x8000000000000000LL ) ak_mpzn_mul_montgomery( res, res, x, p, n0, size );
        uk <<= 1;
     }
  }
  memcpy( z, res, size*sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_mpzn.c  */
/* ----------------------------------------------------------------------------------------------- */
