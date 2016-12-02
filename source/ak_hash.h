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
/*   ak_hash.h                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_HASH_H__
#define __AK_HASH_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>
 #include <ak_libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Тип данных, определяющий набор перестановок, используемых в ГОСТ 28147-89 и ГОСТ Р 34.11-94.   */
 typedef ak_uint8 kbox[8][16];
 typedef kbox *ak_kbox;

/*! Тип данных, реализующий перестановки на множестве из 8 бит */
 typedef ak_uint8 sbox[256];
 typedef sbox *ak_sbox;

/* ----------------------------------------------------------------------------------------------- */
 int ak_kbox_to_sbox( const ak_kbox k, sbox k21, sbox k43, sbox k65, sbox k87 );

/* ----------------------------------------------------------------------------------------------- */
/*! функция создания контекста хеширования */
 typedef ak_hash ( ak_function_hash )( void );
/*! функция очистки контекста хеширования                                                          */
 typedef void ( ak_function_hash_clean )( ak_hash );
/*! функция получения результата хеширования                                                       */
 typedef void ( ak_function_hash_get_code )( ak_hash, ak_pointer );
/*! итерационная функция хеширования                                                               */
 typedef void ( ak_function_hash_update )( ak_hash, const ak_pointer , const ak_uint64 );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий контекст алгоритима хеширования                                      */
 struct hash {
  /*! \brief размер обрабатываемого блока входных данных */
   size_t bsize;
  /*! \brief размер выходного блока (хеш-кода) */
   size_t hsize;
  /*! \brief указатель на внутренние данные контекста */
   ak_pointer data;
  /*! \brief OID алгоритма хеширования */
   ak_oid oid;
  /*! \brief функция очистки контекста */
   ak_function_hash_clean *clean;
  /*! \brief функция обновления состояния контекста */
   ak_function_hash_update *update;
  /*! \brief функция завершения вычислений и получения конечного результата */
   ak_function_hash_update *final;
  /*! \brief функция получения результата вычислений */
   ak_function_hash_get_code *code;
 };

/* ----------------------------------------------------------------------------------------------- */
 ak_hash ak_hash_new( const size_t );
 ak_bool ak_hash_test_streebog256( void );
 ak_bool ak_hash_test_streebog512( void );
 ak_bool ak_hash_test_sha256( void );
 ak_bool ak_hash_test_sha512( void );
 ak_bool ak_hash_test_gosthash94( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hash.h  */
/* ----------------------------------------------------------------------------------------------- */
