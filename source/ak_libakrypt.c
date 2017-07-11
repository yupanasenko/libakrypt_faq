/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_libakrypt.c                                                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип данных для хранения значений опций библиотеки */
 static struct libakrypt_options_ctx {
 /*! \brief Уровень вывода сообщений выполнения функций библиотеки */
  ak_uint32 log_level;
 /*! \brief Ресурс использования ключа (в блоках) алгоритма ГОСТ 28147-89 (Магма) */
  ak_uint32 cipher_key_magma_block_resource;
 /*! \brief Ресурс использования ключа (в блоках) алгоритма ГОСТ 34.12-2015 (Кузнечик) */
  ak_uint32 cipher_key_kuznechik_block_resource;
 /*! \brief Длина номера ключа в байтах */
  ak_uint32 key_number_length;
 /*! \brief Количество итераций в алгоритме PBKDF2 */
  ak_uint32 pbkdf2_iteration_count;
}
 libakrypt_options =
{
  ak_log_standard,
  4194304,  /* константа расчитана для объема в 250 Mb (по 64 бита) */
  8388608,  /* константа расчитана для объема в 1Gb (по 128 бит) */
  16,
  2000
};

/* ----------------------------------------------------------------------------------------------- */
 int ak_log_get_level( void ) { return libakrypt_options.log_level; }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Установка уровня аудита библиотеки.

  Все сообщения библиотеки могут быть разделены на три уровня.

  \li Первый уровень аудита определяется константой \ref ak_log_none. На этом уровне выводятся
  сообщения об ошибках, а также минимальный набор сообщений, включающий в себя факт
  успешного тестирования работоспособности криптографических механизмов.

  \li Второй уровень аудита определяется константой \ref ak_log_standard. На этом уровене
  выводятся все сообщения из первого уровня, а также сообщения о фактах использования
  ключевой информации.

  \li Третий (максимальный) уровень аудита определяется константой \ref ak_log_maximum.
  На этом уровне выводятся все сообщения, доступные на первых двух уровнях, а также
  сообщения отладочного характера, позхволяющие прослдедить логику работы функций библиотеки.

  \param level Уровень аудита, может принимать значения \ref ak_log_none,
  \ref ak_log_standard и \ref ak_log_maximum.

  \return Функция всегда возвращает ak_error_ok (ноль).                                            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_level( int level )
{
 if( level >= ak_log_maximum ) {
   libakrypt_options.log_level = ak_log_maximum;
   return ak_error_ok;
 }
 if( level <= ak_log_none ) {
   libakrypt_options.log_level = ak_log_none;
   return ak_error_ok;
 }
 libakrypt_options.log_level = ak_log_standard;
return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_version( void )
{
#ifdef LIBAKRYPT_VERSION
  return LIBAKRYPT_VERSION;
#else
  return "0.5";
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность определения базовых типов данных
   \return В случе успешного тестирования возвращает ak_true (истина).
   В противном случае возвращается ak_false.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_libakrypt_test_types( void )
{
 if( sizeof( ak_int8 ) != 1 ) {
   ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int8 type" );
   return ak_false;
 }
 if( sizeof( ak_uint8 ) != 1 ) {
   ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint8 type" );
   return ak_false;
 }
 if( sizeof( ak_int32 ) != 4 ) {
   ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int32 type" );
   return ak_false;
 }
 if( sizeof( ak_uint32 ) != 4 ) {
   ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint32 type" );
   return ak_false;
 }
 if( sizeof( ak_int64 ) != 8 ) {
   ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int64 type" );
   return ak_false;
 }
 if( sizeof( ak_uint64 ) != 8 ) {
   ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint64 type" );
   return ak_false;
 }

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "library applies __m128i base type" );
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция должна вызываться перед использованием криптографических механизмов библиотеки.

   Пример использования функции.

   \code
    int main( void )
   {
     if( ak_libakrypt_create( NULL ) != ak_true ) {
       // инициализация выполнена не успешна => выход из программы
       return ak_libakrypt_destroy();
     }

     // ... здесь код программы ...

    return ak_libakrypt_destroy();
   }
   \endcode

   \param logger Указатель на функцию аудита. Может быть равен NULL.
   \return Функция возвращает ak_true (истина) в случае успешной инициализации и тестирования
   библиотеки. В противном случае, возвращается ak_false. Код ошибки может быть получен с помощью
   вызова функции ak_error_get_value()                                                            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create( ak_function_log *logger )
{
 int error;
   ak_error_set_value( error = ak_error_ok );

 /* инициализируем систему аудита (вывод сообщений) */
   if(( error = ak_log_set_function( logger )) != ak_error_ok ) {
     ak_error_message( error, __func__ , "audit mechanism not started" );
     return ak_false;
   }

 /* проверяем длины фиксированных типов данных */
   if( ak_libakrypt_test_types( ) != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "sizes of predefined types is wrong" );
     return ak_false;
   }

 /* считываем настройки криптографических алгоритмов */

 /* инициализируем механизм обработки идентификаторов библиотеки */
   if(( error = ak_oids_create()) != ak_error_ok ) {
     ak_error_message( error, __func__ , "OID's support not started" );
     return ak_false;
   }

 /* инициализируем структуру управления контекстами */
   if(( error = ak_libakrypt_create_context_manager()) != ak_error_ok ) {
     ak_error_message( error, __func__, "initialization of context manager is wrong" );
     return ak_false;
   }

 /* инициализируем механизм обработки секретных ключей пользователей */

 /* тестируем работу функций хеширования */

 /* тестируем работу алгоритмов блочного шифрования */

 /* тестируем работу алгоритмов выработки имитовставки */

 /* тестируем корректность реализации операций с эллиптическими кривыми в короткой форме Вейерштрасса */

 ak_error_message( ak_error_ok, __func__ , "all crypto mechanisms tested successfully" );
return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_destroy( void )
{
  int error = ak_error_get_value();
  if( error != ak_error_ok )
    ak_error_message( error, __func__ , "before destroing library holds an error" );

 /* деактивируем структуру управления контекстами */
  if(( error = ak_libakrypt_destroy_context_manager()) != ak_error_ok )
    ak_error_message( error, __func__, "destroying of context manager is wrong" );

 /* деактивируем механизм поддержки OID */
  if(( error = ak_oids_destroy()) != ak_error_ok )
    ak_error_message( error, __func__ , "OID's support not properly destroyed" );

  ak_error_message( ak_error_ok, __func__ , "all crypto mechanisms successfully destroyed" );
 return ak_error_get_value();
}

/* ----------------------------------------------------------------------------------------------- */
/*! \include doc/libakrypt.dox                                                                     */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
