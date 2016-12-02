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
/*   ak_skey.h                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_SKEY_H__
#define __AK_SKEY_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 struct skey;
/*! \brief Указатель на структуру секретного ключа */
 typedef struct skey *ak_skey;

/* ----------------------------------------------------------------------------------------------- */
 struct cipher_key;
/*! \brief Указатель на структуру ключа блочного алгоритма шифрования */
 typedef struct cipher_key *ak_cipher_key;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Однопараметрическая функция для проведения действий с секретным ключом                  */
 typedef int ( ak_function_skey )( ak_skey );
/*! \brief Однопараметрическая функция для проведения действий с секретным ключом                  */
 typedef ak_bool ( ak_function_skey_check )( ak_skey );

/* ----------------------------------------------------------------------------------------------- */
/*! Функция зашифрования/расширования одного блока информации */
 typedef void ( ak_function_cipher_key )( ak_skey, ak_pointer, ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий контекст секретного ключа                                            */
 struct skey {
  /*! \brief ключ */
   ak_buffer key;
  /*! \brief маска ключа */
   ak_buffer mask;
  /*! \brief генератор случайных масок ключа */
   ak_random generator;
  /*! \brief контрольная сумма ключа */
   ak_buffer icode;
  /*! \brief уникальный номер ключа */
   ak_buffer number;
  /*! \brief указатель на внутренние данные ключа */
   ak_pointer data;

  /*! \brief указатель на функцию маскирования ключа */
   ak_function_skey *set_mask;
  /*! \brief указатель на функцию изменения маски ключа (перемаскирования) */
   ak_function_skey *remask;
  /*! \brief указатель на функцию вычисления контрольной суммы */
   ak_function_skey *set_icode;
  /*! \brief указатель на функцию проверки контрольной суммы */
   ak_function_skey_check *check_icode;
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий контекст ключа блочного алгоритма шифрования                         */
 struct cipher_key {
  /*! \brief Указатель на секретный ключ */
   ak_skey key;
  /*! \brief OID алгоритма шифрования */
   ak_oid oid;
  /*! \brief Ресурс использования ключа шифрования (в блоках) */
   ak_uint32 resource;
  /*! \brief Длина блока обрабатываемых данных в байтах */
   ak_uint32 block_size;

  /*! \brief Функция заширования одного блока информации */
   ak_function_cipher_key *encrypt;
  /*! \brief Функция расширования одного блока информации */
   ak_function_cipher_key *decrypt;
  /*! \brief Функция развертки ключа */
   ak_function_skey *init_keys;
  /*! \brief Функция развертки ключа */
   ak_function_skey *delete_keys;

};

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_create( ak_skey );
 int ak_skey_destroy( ak_skey );
 ak_skey ak_skey_new( void );
 ak_pointer ak_skey_delete( ak_pointer );

 int ak_skey_set_mask_additive( ak_skey );
 int ak_skey_set_mask_xor( ak_skey );
 int ak_skey_remask_additive( ak_skey );
 int ak_skey_remask_xor( ak_skey );
 int ak_skey_set_icode_additive( ak_skey );
 int ak_skey_set_icode_xor( ak_skey );
 ak_bool ak_skey_check_icode_additive( ak_skey );
 ak_bool ak_skey_check_icode_xor( ak_skey );
 int ak_skey_assign_buffer( ak_skey , ak_buffer );
/*! \brief Функция присваивает ключу уникальный номер */
 int ak_skey_assign_unique_number( ak_skey );

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_lock( ak_skey );
 int ak_skey_unlock( ak_skey );

/* ----------------------------------------------------------------------------------------------- */
 int ak_cipher_key_create( ak_cipher_key );
 int ak_cipher_key_destroy( ak_cipher_key );
 ak_cipher_key ak_cipher_key_new( void );
 ak_pointer ak_cipher_key_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
 ak_cipher_key ak_cipher_key_new_magma_buffer( ak_oid, ak_buffer );
 ak_cipher_key ak_cipher_key_new_magma_random( ak_oid, ak_random );
/*! \brief Функция создает ключ алгоритма Кузнечик (ГОСТ Р 34.12-2015) с заданным значением */
 ak_cipher_key ak_cipher_key_new_kuznetchik_buffer( ak_buffer );
/*! \brief Функция создает ключ алгоритма Кузнечик (ГОСТ Р 34.12-2015) со случайным значением */
 ak_cipher_key ak_cipher_key_new_kuznetchik_random( ak_random );

 /*
   ak_cipher_key ak_cipher_key_new_magma_password( ak_oid, char * );
   ak_cipher_key ak_cipher_key_new_kuznetchik_password( ak_oid, char * );
 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_cipher_key_get_resource( ak_cipher_key , ak_uint32 * );
 int ak_cipher_key_encrypt_ecb( ak_cipher_key , ak_pointer , ak_pointer , size_t );
 int ak_cipher_key_decrypt_ecb( ak_cipher_key , ak_pointer , ak_pointer , size_t );

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_cipher_key_test_magma( void );
 ak_bool ak_cipher_key_test_kuznetchik( void );
 int ak_crypt_kuznetchik_init_tables( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.h  */
/* ----------------------------------------------------------------------------------------------- */
