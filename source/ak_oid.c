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

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Максимально возможное количество идентификаторов объектов в библиотеке */
 #define ak_oids_array_count (64)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Статическая структура указателей на массив OID библиотеки */
 static struct {
   ak_oid array[ak_oids_array_count];
   size_t count;
 } global_oids_array;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Мьютекс для блокировки массива OID'ов при добавлении новых значений. */
 static pthread_mutex_t ak_oids_add_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция добавляет новый OID в массив.
    @param oid Контекст добавляемого OID
    @return В случае успеха функция возвращает ak_error_ok. В случае ошибки возвращается ее код.   */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_oids_add_oid( ak_oid oid )
{
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to OID" );
    return ak_error_null_pointer;
  }

  pthread_mutex_lock( &ak_oids_add_mutex );
  if( global_oids_array.count >= ak_oids_array_count ) {
    ak_error_message( ak_error_oid_index, __func__ , "new oid exceeds permissible bounds" );
    pthread_mutex_unlock( &ak_oids_add_mutex );
    return ak_error_oid_index;
  }

  global_oids_array.array[ global_oids_array.count ] = oid;
  global_oids_array.count++;
  pthread_mutex_unlock( &ak_oids_add_mutex );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return функция возвращает ak_error_ok (ноль) в случае успеха. В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oids_create( void )
{
  size_t idx = 0;
  for( idx = 0; idx < ak_oids_array_count; idx++ ) global_oids_array.array[ idx ] = NULL;
  global_oids_array.count = 0;

 /* добавляем идентификаторы алгоритмов выработки псевдо-случайных последовательностей.
    значения OID находятся в дереве библиотеки: 1.2.643.2.52.1.1 - генераторы ПСЧ  */

  ak_oids_add_oid( ak_oid_new( random_generator, algorithm,
                                          "lcg", "1.2.643.2.52.1.1.1", (void *)ak_random_new_lcg ));
#ifdef __linux__
  ak_oids_add_oid( ak_oid_new( random_generator, algorithm,
                          "linux-random", "1.2.643.2.52.1.1.2", (void *)ak_random_new_dev_random ));
  ak_oids_add_oid( ak_oid_new( random_generator, algorithm,
                        "linux-urandom", "1.2.643.2.52.1.1.3", (void *)ak_random_new_dev_urandom ));
#endif
#ifdef _WIN32
  ak_oids_add_oid( ak_oid_new( random_generator, algorithm,
                                      "winrtl", "1.2.643.2.52.1.4", (void *)ak_random_new_winrtl ));
#endif

 /* идентификаторы отечественных криптографических алгоритмов
    взяты согласно перечню OID c http://tk26.ru/methods/OID_TK_26/index.php  и
    из используемых перечней КриптоПро                                                             */

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return функция возвращает ak_error_ok (ноль) в случае успеха. В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oids_destroy( void )
{
  size_t idx = 0;
  for( idx = 0; idx < ak_oids_array_count; idx++ ) {
     if( global_oids_array.array[ idx ] != NULL )
       global_oids_array.array[ idx ] = ak_oid_delete( global_oids_array.array[ idx ] );
  }
  global_oids_array.count = 0;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return функция возвращает количество OID в случае успеха. В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_oids_get_count( void )
{
  return global_oids_array.count;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param idx Индекс OID, целое число, принимающее значение от нуля и меньшее величины,
    возвращаемой функцией ak_oids_get_count()
    @return функция возвращает указатель на OID в случае успеха. В случае возникновения ошибки,
    возвращается NULL, код ошибки помещается в переменную ak_errno.                                */
/* ----------------------------------------------------------------------------------------------- */
 const ak_oid ak_oids_get_oid( const size_t idx )
{
  if( idx >= global_oids_array.count ) {
    ak_error_message( ak_error_oid_index, __func__ , "index exceeds permissible bounds" );
    return NULL;
  }
  return ( const ak_oid ) global_oids_array.array[ idx ];
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param name Строка символов, содержащая читаемое пользователем имя OID
    @return Функция возвращает контекст OID. В случае ошибки возвращается NULL, а код ошибки
    может быть получен с помощью вызова функции ak_error_get_value()                               */
/* ----------------------------------------------------------------------------------------------- */
 const ak_oid ak_oids_find_by_name( const char *name )
{
  size_t idx = 0;
  if( name == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to a name" );
    return NULL;
  }
  /* собственно поиск */
  for( idx = 0; idx < global_oids_array.count; idx++ ) {
     if( global_oids_array.array[ idx ] == NULL  ){
       ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to internal OID" );
       return NULL;
     }
     if( strstr( ak_oid_get_name( global_oids_array.array[ idx ]), name ) != NULL )
       return ( const ak_oid ) global_oids_array.array[ idx ];
  }
  ak_error_message_fmt( ak_error_oid_name , __func__ , "searching OID with wrong name %s", name );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param id Строка символов, содержащая идентификатор OID
    @return Функция возвращает контекст OID. В случае ошибки возвращается NULL, а код ошибки
    может быть получен с помощью вызова функции ak_error_get_value()                               */
/* ----------------------------------------------------------------------------------------------- */
 const ak_oid ak_oids_find_by_id( const char *id )
{
  size_t idx = 0;
  if( id == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to identifier" );
    return NULL;
  }
  /* собственно поиск */
  for( idx = 0; idx < global_oids_array.count; idx++ ) {
     if( global_oids_array.array[ idx ] == NULL  ){
       ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to internal OID" );
       return NULL;
     }
     if( strstr( ak_oid_get_id( global_oids_array.array[ idx ]), id ) != NULL )
       return ( const ak_oid ) global_oids_array.array[ idx ];
  }
  ak_error_message_fmt( ak_error_oid_id, __func__ , "searching OID with wrong identifier %s", id );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             функции класса ak_oid                                               */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значения внутренних полей структуры, описывающий OID
    криптографического механизма или параметра.

    @param oid указатель на структуру, поля которой заполняются
    @param engine тип криптографического механизма
    @param mode режим использования криптографического механизма
    @param name читаемое (пользователем) криптографического механизма или параметра
    @param id строка-идентификатор (последовательность чисел, разделенных точками)
    @param data указатель на данные
    @return В случае успеха возвращается значение ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oid_create( ak_oid oid, ak_oid_engine engine, ak_oid_mode mode,
                                                const char *name, const char *id, ak_pointer data )
{
 if( oid == NULL ) {
  ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
  return ak_error_null_pointer;
 }
 if( name == NULL ) {
  ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid name" );
  return ak_error_null_pointer;
 }
 if( id == NULL ) {
  ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid stlist" );
  return ak_error_null_pointer;
}

 oid->engine = engine;
 oid->mode = mode;
 if( (oid->name = ak_buffer_new_str( name )) == NULL ) {
  ak_error_message( ak_error_out_of_memory, __func__ , "incorrect assignment of oid name" );
  return ak_error_out_of_memory;
 }
 if( (oid->id = ak_buffer_new_str( id )) == NULL ) {
  ak_error_message( ak_error_out_of_memory, __func__ , "incorrect assignment of oid stlist" );
  return ak_error_out_of_memory;
 }
 oid->data = data;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает указатель на структуру struct oid, устанавливает поля этой структуры
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
                                                const char *name, const char *id, ak_pointer data )
{
  ak_oid boid = ( ak_oid ) malloc( sizeof( struct oid ));
  if( boid != NULL ) ak_oid_create( boid, engine, mode, name, id, data );
    else ak_error_message( ak_error_out_of_memory, __func__ , "invalid creation of a new oid" );
  return boid;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает все внутренние поля и уничтожает указатель на структуру OID

    @param oid указатель на структуру struct oid
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_delete( ak_pointer boid )
{
  if( boid != NULL ) {
   ak_oid_destroy( boid );
   free( boid );
  } else ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция уничтожает все данные, хранящиеся в полях структуры struct oid

    @param boid указатель на структуру struct oid
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oid_destroy( ak_oid boid )
{
  if( boid == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
   return ak_error_null_pointer;
  }
  if( boid->name != NULL ) ak_buffer_delete( boid->name );
  if( boid->id != NULL ) ak_buffer_delete( boid->id );
  /* boid->data: не мы выделили память, не нам и освобождать ))) */
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid указатель на структуру struct oid
    @return Возвращается ссылка на строку с описанием имени OID. При возникновении ошибки
    возвращается NULL, а код ошибки помещается в переменную ak_errno.                              */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_oid_get_name( ak_oid oid )
{
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
    return NULL;
  }
  return ak_buffer_get_str( oid->name );
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @param oid указатель на структуру struct oid
     @return Возвращается ссылка на строку с OID. При возникновении ошибки
     возвращается NULL, а код ошибки помещается в переменную ak_errno.                             */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_oid_get_id( ak_oid oid )
{
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
    return NULL;
  }
  return ak_buffer_get_str( oid->id );
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @param oid указатель на структуру struct oid
     @return Возвращается значение криптографического механизма. При возникновении ошибки
     возвращается ее код.                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 const ak_oid_engine ak_oid_get_engine( ak_oid oid )
{
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
    return identifier;
  }
  return oid->engine;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @param oid указатель на структуру struct oid
     @return Возвращается символьное описание криптографического механизма. Данное описание есть
     константная строка, память из под которой не должна удаляться пользователем.
     При возникновении ошибки ее код может быть получен при посощи вызова ak_error_get_value().    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_oid_get_engine_str( ak_oid oid )
{
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
    return ak_null_string;
  }
   switch( oid->engine )
  {
    case undefined_engine:  return "undefined engine";
    case identifier:        return "identifier";
    case block_cipher:      return "block cipher";
    case stream_cipher:     return "stream cipher";
    case hybrid_cipher:     return "hybrid cipher";
    case hash_function:     return "hash function";
    case mac_function:      return "mac function";
    case digital_signature: return "digital signature";
    case random_generator:  return "random generator";
    case update_engine:     return "update engine";
    default:                return ak_null_string;
  }
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @param oid указатель на структуру struct oid
     return Возвращается значение режима криптографического механизма. При возникновении ошибки
     возвращается ее код.                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 const ak_oid_mode ak_oid_get_mode( ak_oid oid )
{
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
    return undefined_mode;
  }
  return oid->mode;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @param oid указатель на структуру struct oid
     @return Возвращается указатель на данные.  При возникновении ошибки
     возвращается NULL, а код ошибки помещается в переменную ak_errno.                             */
/* ----------------------------------------------------------------------------------------------- */
 const ak_pointer ak_oid_get_data( ak_oid oid )
{
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to an oid" );
    return NULL;
  }
 return oid->data;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  \example example-oid.c                                                                        */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
