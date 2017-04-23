/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
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
/*   ak_tools.h                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
/*   Файл содержит описания служебных функций и переменных, не экспортруемых за пределы библиотеки */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef    __AK_TOOLS_H__
 #define    __AK_TOOLS_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Неэкспортируемая функция установления уровня аудита */
 int ak_log_set_level( int );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция считывает настройки библиотеки из конфигурационного файла */
 ak_bool ak_libakrypt_load_options( void );
/*! \brief Функция возвращает ресурс секретного ключа для алгоритмов ГОСТ 28147-89 и Магма */
 ak_uint32 ak_libakrypt_get_magma_resource( void );
/*! \brief Функция возвращает ресурс секретного ключа для алгоритма ГОСТ 34.12-2015 (Кузнечик) */
 ak_uint32 ak_libakrypt_get_kuznechik_resource( void );
/*! \brief Функция возвращает длину номера формируемого библиотекой ключа в байтах */
 ak_uint32 ak_libakrypt_get_key_number_length( void );
/*! \brief Функция возвращает количество итерация для алгоритма pbkdf2 */
 ak_uint32 ak_libakrypt_get_pbkdf2_iteration_count( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обобщенная реализация функции snprintf для различных компиляторов */
 int ak_snprintf( char *str, size_t size, const char *format, ... );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке */
 int ak_error_message_fmt( const int , const char *, const char *, ... );

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.h  */
/* ----------------------------------------------------------------------------------------------- */
