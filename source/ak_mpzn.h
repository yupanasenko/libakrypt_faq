/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014, 2015, 2016 by Axel Kenzo, axelkenzo@mail.ru                               */
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
/*   ak_mpzn.h                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_MPZN_H__
#define    __AK_MPZN_H__

/* ----------------------------------------------------------------------------------------------- */
#include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 #define ak_mpzn256_size     (4)
 #define ak_mpzn512_size     (8)
 #define ak_mpznmax_size    (18)

 #define ak_mpzn256_zero  { 0, 0, 0, 0 }
 #define ak_mpzn256_one   { 1, 0, 0, 0 }
 #define ak_mpzn512_zero  { 0, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpzn512_one   { 1, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpznmax_zero  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Элемент кольца вычетов по модулю \f$2^{256}\f$ */
typedef ak_uint64 ak_mpzn256[ ak_mpzn256_size ];
/*! \brief Элемент кольца вычетов по модулю \f$2^{512}\f$ */
typedef ak_uint64 ak_mpzn512[ ak_mpzn512_size ];
/*! \brief Тип данных для хранения максимально возможного большого числа */
typedef ak_uint64 ak_mpznmax[ ak_mpznmax_size ];

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Присвоение вычету беззнакового целого значения */
 int ak_mpzn_set_ui( ak_uint64 *, const size_t , const ak_uint64 );
/*! \brief Присвоение вычету случайного значения */
 int ak_mpzn_set_random( ak_uint64 *, const size_t , ak_random );
/*! \brief Присвоение вычету случайного значения по фиксированному модулю */
 int ak_mpzn_set_random_modulo( ak_uint64 *, ak_uint64 *, const size_t , ak_random );
/*! \brief Присвоение вычету значения, записанного строкой шестнадцатеричных символов */
 int ak_mpzn_set_hexstr( ak_uint64 *, const size_t , const char * );
/*! \brief Преобразование вычета в строку шестнадцатеричных символов */
 char *ak_mpzn_to_hexstr( ak_uint64 *, const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Сложение двух вычетов */
 ak_uint64 ak_mpzn_add( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычитание двух вычетов */
 ak_uint64 ak_mpzn_sub( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Сравнение двух вычетов */
 int ak_mpzn_cmp( ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Умножение вычета на беззнаковое целое */
 ak_uint64 ak_mpzn_mul_ui( ak_uint64 *, ak_uint64 *, const size_t, const ak_uint64 );
/*! \brief Умножение двух вычетов как целых чисел */
 void ak_mpzn_mul( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для реализации операций с большими числами в представлении Монтгомери */
 struct monty
{
 /*! \brief Простое число, порождающее конечное простое поле */
 ak_uint64 *p;
 /*! \brief Размер простого числа (в словах по 64 бита) */
 size_t size;
 /*! \brief Вспомогательный множитель для арифметики Монтгомери */
 ak_uint64 n;
};
/*! \brief Контекст стуктуры struct monty */
 typedef struct monty *ak_monty;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание структуры struct monty */
 int ak_monty_create( ak_monty , const char *, const size_t , const ak_uint64 );
/*! \brief Создание контекста структуры struct monty */
 ak_monty ak_monty_new( const char *, const size_t , const ak_uint64 );
/*! \brief Уничтожение данных, хранящиеся в полях структуры struct monty */
 int ak_monty_destroy( ak_monty );
/*! \brief Уничтожение структуры ak_monty */
 ak_pointer ak_monty_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Сложение двух вычетов в представлении Монтгомери */
 void ak_mpzn_add_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Сложение двух вычетов в представлении Монтгомери */
 void ak_mpzn_add_montgomery2( ak_uint64 *, ak_uint64 *, ak_uint64 *, const ak_monty );
/*! \brief Умножение двух вычетов в представлении Монтгомери */
 void ak_mpzn_mul_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *,
                                                          ak_uint64 *, ak_uint64, const size_t );
/*! \brief Умножение двух вычетов в представлении Монтгомери */
 void ak_mpzn_mul_montgomery2( ak_uint64 *, ak_uint64 *, ak_uint64 *, const ak_monty );
#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_mpzn.h  */
/* ----------------------------------------------------------------------------------------------- */
