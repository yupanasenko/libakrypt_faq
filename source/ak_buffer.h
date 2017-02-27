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
/*   ak_buffer.h                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_BUFFER_H__
#define    __AK_BUFFER_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения двоичных данных

  Класс рассматривается как хранилище данных, для которых контролируется размер и функции
  выделения/освобождения памяти. Класс может использоваться для хранения строк.                    */
/* ----------------------------------------------------------------------------------------------- */
 struct buffer {
   /*! \brief размер данных (в байтах) */
   size_t size;
   /*! \brief указатель на данные */
   ak_pointer data;
   /*! \brief флаг выделения памяти/владения данными */
   ak_bool flag;
   /*! \brief указатель на функцию выделения памяти под данные */
   ak_function_alloc *alloc;
   /*! \brief указатель на функцию освобождения данных */
   ak_function_free *free;
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация буффера */
 int ak_buffer_create( ak_buffer );
/*! \brief Инициализация буффера и выделение памяти фиксированной длины */
 int ak_buffer_create_size( ak_buffer , const size_t );
/*! \brief Инициализация буффера с заданными обработчиками выделения и освобождения памяти */
 int ak_buffer_create_function_size( ak_buffer ,
                                          ak_function_alloc *, ak_function_free *, const size_t );
/*! \brief Функция освобождает память, выделенную под данные (поле data структуры struct buffer ) */
 int ak_buffer_free( ak_buffer );
/*! \brief Функция выделяет память под данные, хранимые в буффере */
 int ak_buffer_alloc( ak_buffer , const size_t );
/*! \brief Уничтожение данных, хранящиеся в полях структуры struct buffer */
 int ak_buffer_destroy( ak_buffer );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_buffer.h  */
/* ----------------------------------------------------------------------------------------------- */
