/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
/*  ak_hash.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_compress.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct hash в значения по-умолчанию.

    @param ctx указатель на структуру struct hash
    @param data_size Размер внутренних данных контекста в байтах
    @param block_size Размер блока обрабатываемых данных в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_create( ak_hash ctx, const size_t data_size, const size_t block_size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using null pointer to hash context" );
  if( block_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using a zero length of data block length" );
  if( data_size ) {
    if(( ctx->data = malloc( data_size )) == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                      "incorrect internal data memory allocation" );
  } else ctx->data = NULL;

  ctx->bsize =  block_size;
  ctx->hsize =           0;
  ctx->oid =          NULL;
  ctx->clean =        NULL;
  ctx->update =       NULL;
  ctx->finalize =     NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает значения полей структуры struct hash.

  @param ctx указатель на структуру struct hash
  @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
  возвращается ее код.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_destroy( ak_hash ctx )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "destroying null pointer to hash context" );
  if( ctx->data != NULL ) free( ctx->data );

  ctx->bsize =       0;
  ctx->hsize =       0;
  ctx->data =     NULL;
  ctx->oid =      NULL;
  ctx->clean =    NULL;
  ctx->update =   NULL;
  ctx->finalize = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx указатель на контекст хеширования
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hash_delete( ak_pointer ctx )
{
  if( ctx != NULL ) {
      ak_hash_destroy(( ak_hash ) ctx );
      free( ctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to hash context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет хеш-код от заданной области памяти на которую указывает in. Размер памяти
    задается в байтах в переменной size. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param ctx Контекст алгоритма хеширования, должен быть отличен от NULL.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_ptr_context( ak_hash ctx, const ak_pointer in, const size_t size, ak_pointer out )
{
  ak_buffer result = NULL;
  size_t quot = 0, offset = 0;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hash context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to data" );
    return NULL;
  }

  /* вычищаем результаты предыдущих вычислений */
  ctx->clean( ctx );
  quot = size/ctx->bsize;
  offset = quot*ctx->bsize;
  /* вызываем, если длина сообщения не менее одного полного блока */
  if( quot > 0 ) ctx->update( ctx, in, offset );
  /* обрабатываем хвост */
  result = ctx->finalize( ctx, (unsigned char *)in + offset, size - offset, out );
  /* очищаем за собой данные, содержащиеся в контексте */
  ctx->clean( ctx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет хеш-код от заданного файла. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param ctx Контекст алгоритма хеширования, должен быть отличен от NULL.
    @param filename Имя файла, для которого вычисляется значение хеш-кода.
    @param out Область памяти, куда будет помещен результат.
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_file_context( ak_hash ctx, const char *filename, ak_pointer out )
{
  struct compress comp;
  int error = ak_error_ok;
  ak_buffer result = NULL;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hash context" );
    return NULL;
  }

  if( ak_compress_create_hash( &comp, ctx ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation a compress context" );
    return NULL;
  }

  result = ak_compress_file( &comp, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect hash code calculation" );

  ak_compress_destroy( &comp );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                               реализация интерфейсных функций                                   */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание дескриптора для функции бесключевого хеширования.
    Для существующего контекста функции бесключевого хеширования, под который ранее выделена память
    с помощью вызова malloc(), функция создает его дескриптор,
    и размещает контекст во внутренней структуре хранения контекстов.

    @param generator контекст функции бесключевого хеширования
    (контекст не должен быть указателем на статическую переменную).
    @return В случае успешного выполнения возвращается дескриптор контекста. В случае возникновения
    ошибки возвращается \ref ak_error_wrong_handle. Код ошибки может быть получен
    с помощью вызова функции ak_error_get_value().                                                 */
/* ----------------------------------------------------------------------------------------------- */
 static ak_handle ak_hash_new_handle( ak_hash ctx )
{
  ak_context_manager manager = NULL;
  ak_handle handle = ak_error_wrong_handle;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "using a non initialized context manager" );
    ctx = ak_hash_delete( ctx );
    return ak_error_wrong_handle;
  }

 /* создаем элемент структуры управления контекстами */
  if(( handle = ak_context_manager_add_node(
           manager, ctx, hash_function, "", ak_hash_delete )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of context manager node" );
    ctx = ak_random_delete( ctx );
    return ak_error_wrong_handle;
  }

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст алгоритма хеширования, регламентируемого ГОСТ Р 34.11-94 (в настоящее
    время стандарт выведен из действия) и возвращает пользователю дескриптор созданного
    контекста.

    @param oid Дескриптор таблиц замен, используемых в алгорииме хэширования.
    @return Функция возвращает десткриптор созданного контекста. В случае возникновения ошибки
    возвращается \ref ak_error_wrong_handle. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_hash_new_gosthash94( ak_handle oid )
{
  ak_hash ctx = NULL;
  int error = ak_error_ok;

 /* создаем контекст функции хэширования */
  if(( ctx = malloc( sizeof( struct hash ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "wrong creation of hash function context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_hash_create_gosthash94( ctx, oid )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of hash function context" );
    free( ctx );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_hash_new_handle( ctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст функции хеширования, регламентируемой ГОСТ Р 34.11-94 (в настоящее
    время стандарт выведен из действия) с фиксированным значением таблицам замен,
    используемых в ранних версиях КриптоПро CSP.

    @return Функция возвращает десткриптор созданного контекста. В случае возникновения ошибки
    возвращается \ref ak_error_wrong_handle. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_hash_new_gosthash94_csp( void )
{
 return ak_hash_new_gosthash94( ak_oid_find_by_name( "id-gosthash94-CryptoPro-ParamSetA" ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст алгоритма хеширования, регламентируемого ГОСТ Р 34.11-2012,
    с длиной хэш-кода равной 256 бит (Стрибог256),
    и возвращает пользователю дескриптор созданного контекста.

    @return Функция возвращает десткриптор созданного контекста. В случае возникновения ошибки
    возвращается \ref ak_error_wrong_handle. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_hash_new_streebog256( void )
{
  ak_hash ctx = NULL;
  int error = ak_error_ok;

 /* создаем контекст функции хэширования */
  if(( ctx = malloc( sizeof( struct hash ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "wrong creation of hash function context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_hash_create_streebog256( ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of hash function context" );
    free( ctx );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_hash_new_handle( ctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст алгоритма хеширования, регламентируемого ГОСТ Р 34.11-2012,
    с длиной хэш-кода равной 512 бит (Стрибог512),
    и возвращает пользователю дескриптор созданного контекста.

    @return Функция возвращает десткриптор созданного контекста. В случае возникновения ошибки
    возвращается \ref ak_error_wrong_handle. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_hash_new_streebog512( void )
{
  ak_hash ctx = NULL;
  int error = ak_error_ok;

 /* создаем контекст функции хэширования */
  if(( ctx = malloc( sizeof( struct hash ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "wrong creation of hash function context" );
    return ak_error_wrong_handle;
  }

 /* инициализируем его */
  if(( error = ak_hash_create_streebog512( ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of hash function context" );
    free( ctx );
    return ak_error_wrong_handle;
  }

 /* помещаем в стуктуру управления контекстами */
 return ak_hash_new_handle( ctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid_handle дескриптор OID бесключевой функции хеширования.
    @return Функция возвращает дескриптор созданного контекста функции хеширования.
    Если дескриптор не может быть создан, или oid не соотвествует функции хеширования,
    то возбуждается ошибка и возвращается значение \ref ak_error_wrong_handle. Кош ошибки может
    быть получен с помощью вызова функции ak_error_get_value().                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_hash_new_oid( ak_handle oid_handle )
{
  ak_handle hash_handle = ak_error_wrong_handle;
  ak_oid oid = ak_handle_get_context( oid_handle, oid_engine );

  /* проверяем, что handle от OID */
   if( oid == NULL ) {
     ak_error_message( ak_error_get_value(), __func__ , "using wrong value of handle" );
     return ak_error_wrong_handle;
   }
  /* проверяем, что OID от бесключевой функции хеширования */
   if( oid->engine != hash_function ) {
     ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
     return ak_error_wrong_handle;
   }
  /* проверяем, что OID от алгоритма, а не от параметров */
   if( oid->mode != algorithm ) {
     ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );
     return ak_error_wrong_handle;
   }
  /* проверяем, что производящая функция определена */
   if( oid->func == NULL ) {
     ak_error_message( ak_error_undefined_function, __func__ ,
                                     "using oid with undefined constructor function" );
     return ak_error_wrong_handle;
   }

  /* только теперь создаем контекст функции хеширования */
   if(( hash_handle = ((ak_function_hash *) oid->func)()) == ak_error_wrong_handle )
     ak_error_message( ak_error_get_value(), __func__ , "wrong creation of hash function handle");

 return hash_handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle Дескриптор контекста функции хеширования.
    @return Функция возвращает количество байт, которые занимает результат примения функции
    хэширования. В случае, если дескриптор задан неверно, то возвращаемое значение не определено.
    В этом случае код ошибки моет быть получен с помощью вызова функции ak_error_get_value().      */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hash_get_code_size( ak_handle handle )
{
  ak_hash ctx = NULL;

  if(( ctx = ak_handle_get_context( handle, hash_function )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );

 return ctx->hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param handle Дескриптор контекста функции хеширования.
    @return Функция возвращает количество байт, которые образуют один обрабатываемый функцией блок
    данных.
    В случае, если дескриптор задан неверно, то возвращаемое значение не определено.
    В этом случае код ошибки моет быть получен с помощью вызова функции ak_error_get_value().      */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hash_get_block_size( ak_handle handle )
{
  ak_hash ctx = NULL;

  if(( ctx = ak_handle_get_context( handle, hash_function )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );

 return ctx->bsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет хеш-код от заданной области памяти на которую указывает in. Размер памяти
    задается в байтах в переменной size. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param handle Дескриптор алгоритма хеширования. Должен быть получен с помощью вызова одной из
    экспортируемых функций `ak_hash_new_<алгоритм>()`.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_ptr( ak_handle handle, const ak_pointer in, const size_t size, ak_pointer out )
{
  ak_buffer buffer = NULL;
  ak_hash ctx = NULL;

  if(( ctx = ak_handle_get_context( handle, hash_function )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );
    return NULL;
  }

  return ( buffer = ak_hash_ptr_context( ctx, in, size, out ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет хеш-код от заданного файла. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param handle Дескриптор алгоритма хеширования. Должен быть получен с помощью вызова одной из
    экспортируемых функций `ak_hash_new_<алгоритм>()`.
    @param filename Имя файла, для которого вычисляется значение хеш-кода.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_file( ak_handle handle, const char *filename, ak_pointer out )
{
  ak_buffer buffer = NULL;
  ak_hash ctx = NULL;

  if(( ctx = ak_handle_get_context( handle, hash_function )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong handle" );
    return NULL;
  }

  return ( buffer = ak_hash_file_context( ctx, filename, out ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-hash.c
    \example example-hash-oids.c                                                                   */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hash.c  */
/* ----------------------------------------------------------------------------------------------- */
