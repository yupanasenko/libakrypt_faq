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
/*   ak_oid.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*                             функции класса ak_oid                                               */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значения внутренних полей структуры, описывающий OID
    криптографического механизма или параметра.

    @param oid Контекст идентификатора криптографическоого механизма
    @param engine тип криптографического механизма
    @param mode режим использования криптографического механизма
    @param name читаемое (пользователем) криптографического механизма или параметра
    @param id строка-идентификатор (последовательность чисел, разделенных точками)
    @param data указатель на данные
    @return В случае успеха возвращается значение ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oid_create( ak_oid oid, ak_oid_engine engine, ak_oid_mode mode,
                                  const char *name, const char *id, ak_function_pointer_void *data )
{
 int error = ak_error_ok;

  if( oid == NULL ) return ak_error_message( ak_error_null_pointer,
                                                         __func__ , "using null pointer to oid" );
  if( name == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                               "using null pointer to oid name" );
  if( id == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to oid numer sequence" );
 /* присваиваем имя */
  ak_buffer_create( &oid->name );
  if(( error = ak_buffer_set_str( &oid->name, name )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of oid name");
    ak_oid_destroy( oid );
    return error;
  }

 /* присваиваем идентификатор */
  ak_buffer_create( &oid->id );
  if(( error = ak_buffer_set_str( &oid->id, id )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of oid identifier" );
    ak_oid_destroy( oid );
    return error;
  }

 /* присваиваем остальные поля */
  oid->engine = engine;
  oid->mode = mode;
  oid->data = data;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция уничтожает все данные, хранящиеся в полях структуры struct oid

    @param oid Контекст идентификатора криптографического механизма
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oid_destroy( ak_oid oid )
{
  int error = ak_error_ok;

  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using null pointer to oid" );
  if(( error = ak_buffer_destroy( &oid->name )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying oid's name buffer" );

  if(( error = ak_buffer_destroy( &oid->id )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying oid's identifier buffer" );

  oid->engine = undefined_engine;
  oid->mode = undefined_mode;
  oid->data = NULL;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст идентификатора криптографического механизма, устанавливает его поля
    в заданные значения по-умолчанию и возвращает указатель на созданную структуру.

    @param engine тип криптографического механизма
    @param mode режим использования криптографического механизма
    @param name читаемое (пользователем) криптографического механизма или параметра
    @param id строка-идентификатор (последовательность чисел, разделенных точками)
    @param data указатель на данные
    @return Если указатель успешно создан, то он и возвращается. В случае возникновения ошибки
    возвращается NULL. Код ошибки помещается в переменную ak_errno.                                */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_new( ak_oid_engine engine, ak_oid_mode mode,
                                 const char *name, const char *id, ak_function_pointer_void *data )
{
  ak_oid oid = ( ak_oid ) malloc( sizeof( struct oid ));

    if( oid != NULL ) ak_oid_create( oid, engine, mode, name, id, data );
      else ak_error_message( ak_error_out_of_memory, __func__ , "invalid creation of a new oid" );
  return oid;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает все внутренние поля и уничтожает контекст идентификатора
   криптографического механизма.

    @param oid указатель на структуру struct oid
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_delete( ak_pointer oid )
{
  if( oid != NULL ) {
    ak_oid_destroy( oid );
    free( oid );
  } else ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to oid" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*                     реализация функций доступа к глобальному списку OID                         */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция добавляет новый OID в массив.
    @param oid Контекст добавляемого OID
    @return В случае успеха функция возвращает ak_error_ok. В случае ошибки возвращается ее код.   */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_oids_add_oid( ak_context_manager manager, ak_oid oid )
{
  ak_handle handle = ak_error_wrong_handle;

  if( manager == NULL ) return ak_error_message( ak_error_get_value(), __func__ ,
                                                      "using a non initialized context manager" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__
                                                                , "using a null pointer to oid" );

 /* создаем элемент структуры управления контекстами */
  if(( handle = ak_context_manager_add_node(
                       manager, oid, oid_engine, "", ak_oid_delete )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of context manager node" );
    oid = ak_oid_delete( oid );
    return ak_error_wrong_handle;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return функция возвращает ak_error_ok (ноль) в случае успеха. В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oids_create( void )
{
  int error = ak_error_ok;
  ak_context_manager manager = NULL;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL )
    return ak_error_message( error = ak_error_get_value(), __func__ ,
                                                        "using a non initialized context manager" );

 /* добавляем идентификаторы алгоритмов выработки псевдо-случайных последовательностей.
    значения OID находятся в дереве библиотеки: 1.2.643.2.52.1.1 - генераторы ПСЧ  */

  if(( error = ak_oids_add_oid( manager, ak_oid_new( random_generator, algorithm, "lcg",
            "1.2.643.2.52.1.1.1", (ak_function_pointer_void *)ak_random_new_lcg ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

#ifdef __linux__
  if(( error = ak_oids_add_oid( manager, ak_oid_new( random_generator, algorithm, "linux-random",
     "1.2.643.2.52.1.1.2", (ak_function_pointer_void *)ak_random_new_dev_random ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( random_generator, algorithm, "linux-urandom",
    "1.2.643.2.52.1.1.3", (ak_function_pointer_void *)ak_random_new_dev_urandom ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );
#endif
#ifdef _WIN32
  if(( error = ak_oids_add_oid( manager, ak_oid_new( random_generator, algorithm, "winrtl",
         "1.2.643.2.52.1.1.4", (ak_function_pointer_void *)ak_random_new_winrtl ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );
#endif

 /* идентификаторы отечественных криптографических алгоритмов
    взяты согласно перечню OID c http://tk26.ru/methods/OID_TK_26/index.php  и
    из используемых перечней КриптоПро                                                             */

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  \example example-oid.c                                                                        */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
