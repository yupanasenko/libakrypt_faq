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
/*   ak_random.h                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_RANDOM_H__
#define    __AK_RANDOM_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 typedef int ( ak_function_random )( ak_random );
 typedef int ( ak_function_random_uint64 )( ak_random, const ak_uint64 );
 typedef int ( ak_function_random_ptr_const )( ak_random, const ak_pointer, const size_t );
 typedef ak_uint8 ( ak_function_random_rand_uint8 )( ak_random );
 typedef ak_uint64 ( ak_function_random_rand_uint64 )( ak_random );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий произвольный генератор псевдо-случайных чисел.                       */
/* ----------------------------------------------------------------------------------------------- */
 struct random {
   /*! \brief указатель на внутренние структуры данных */
   ak_pointer data;

   /*! \brief указатель на функцию выработки следующего внутреннего состояния */
   ak_function_random *next;
   /*! \brief указатель на функцию инициализации генератора случайным значением */
   ak_function_random *randomize;
   /*! \brief указатель на функцию инициализации генератора заданным значением */
   ak_function_random_uint64 *randomize_uint64;
   /*! \brief указатель на функцию инициализации генератора заданным массивом значений */
   ak_function_random_ptr_const *randomize_ptr;
   /*! \brief указатель на функцию выработки псевдо-случайного байта */
   ak_function_random_rand_uint8 *uint8;
   /*! \brief указатель на функцию выработки псевдо-случайного слова, размером 64 бита */
   ak_function_random_rand_uint64 *uint64;
   /*! \brief указатель на функцию выработки последователности псевдо-случайных байт */
   ak_function_random_ptr_const *random;
   /*! \brief указатель на функцию освобождения памяти внутренней структуры данных */
   ak_function_free *free;
 };

/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create( ak_random );
 ak_random ak_random_new( void );

 int ak_random_destroy( ak_random );
 ak_uint64 ak_random_value( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_random.h  */
/* ----------------------------------------------------------------------------------------------- */
