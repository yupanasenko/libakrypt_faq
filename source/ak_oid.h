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
/*   ak_oid.h                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_OID_H__
#define    __AK_OID_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_buffer.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения идентификаторов криптографических механизмов и их данных             */
/*! OID (Object IDentifier) это уникальная последовательность чисел, разделенных точками.

    OID'ы могут быть присвоены любому криптографическому механизму (алгоритму,
    схеме, протоколу), а также параметрам этих механизмов.
    Использование OID'в позволяет однозначно определять тип криптографического механизма или
    значения его параметров на этапе выполнения программы, а также
    однозначно связывать данные (как правило ключевые) с алгоритмами, в которых эти данные
    используются.

    Примеры использования OID приводятся в разделе \ref toid.                                      */
/* ----------------------------------------------------------------------------------------------- */
 struct oid {
  /*! \brief криптографический механизм   */
   ak_oid_engine engine;
  /*! \brief режим использования криптографического алгоритма */
   ak_oid_mode mode;
  /*! \brief читаемое имя (для пользователя) */
   ak_buffer name;
  /*! \brief собственно OID (cтрока чисел, разделенных точками) */
  ak_buffer id;
  /*! \brief указатель на данные */
   ak_pointer *data;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация внутреннего массива с OID библиотеки */
 int ak_oids_create( void );
/*! \brief Удаление внутреннего массива с OID библиотеки */
 int ak_oids_destroy( void );
/*! \brief Инициализация контекста OID */
 int ak_oid_create( ak_oid oid, ak_oid_engine , ak_oid_mode ,
                                                        const char * , const char * , ak_pointer );
/*! \brief Создание контекста OID */
 ak_oid ak_oid_new( ak_oid_engine , ak_oid_mode , const char * , const char * , ak_pointer );
/*! \brief Освобождение памяти из под контекста OID */
 ak_pointer ak_oid_delete( ak_pointer );
/*! \brief Освобождение памяти из под данных, хранящихся в контексте OID */
 int ak_oid_destroy( ak_oid );
/*! \brief Получение указателя на внутренние данные OID */
 const ak_pointer ak_oid_get_data( ak_oid );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.h  */
/* ----------------------------------------------------------------------------------------------- */

