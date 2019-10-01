/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_context_manager.c                                                                      */
/*  - содержит реализацию функций для управления контекстами.                                      */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef LIBAKRYPT_HAVE_PTHREAD
 #include <pthread.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hmac.h>
 #include <ak_bckey.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*                                   класс ak_context_node                                         */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает oid из указателя на объект (контекст), тип которого задается
    параметром engine.
    @param ctx Контекст объетка.
    @param engine Тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @return Функция возвращает указатель на OID объекта.
    В случае возникновения ошибки возвращается NULL. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 static ak_oid ak_context_node_get_context_oid( const ak_pointer ctx, const oid_engines_t engine )
{
  ak_oid oid = NULL;
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to context" );
    return NULL;
  }

 /* вытаскиваем oid, присвоенный при создании контекста */
  switch( engine ) {
    case random_generator:
                  oid = (( ak_random ) ctx )->oid;
                  break;
    case hash_function:
                  oid = (( ak_hash ) ctx )->oid;
                  break;
    case hmac_function:
                  oid = (( ak_hmac ) ctx )->key.oid;
                  break;
    case block_cipher:
                  oid = (( ak_bckey ) ctx )->key.oid;
                  break;
    default: oid = NULL;
  }

 /* проверка найденного */
  if( oid == NULL ) {
    ak_error_message( ak_error_oid_engine, __func__, "using unsupported oid engine" );
   } else {
       /* проверка существования данного адреса */
        if( !ak_oid_context_check( oid )) {
          oid = NULL;
          ak_error_message( ak_error_wrong_oid, __func__, "wrong pointer to context" );
        }
     }

 return oid;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает новый элемент структуры управления контекстами, заполняя его поля значениями,
    передаваемыми в качестве аргументов функции.

    @param ctx Контекст, который будет храниться в структуре управления контекстами.
    К моменту вызова функции контекст должен быть отлиен от NULL и инфициализирован.
    @param id Идентификатор контекста, величина по которой пользовать может получить доступ
    к функциям, реализующим действия с контекстом.
    @param engine тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @param description пользовательское описание контекста, может быть NULL
    @return Функция возвращает указатель на созданный элемент структуры управления контекстами.
    В случае возникновения ошибки возвращается NULL. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_context_node ak_context_node_new( const ak_pointer ctx, const ak_handle handle,
                                               const oid_engines_t engine, const char *description )
{
  size_t len = 0;
  ak_oid oid = NULL;
  int error = ak_error_ok;
  ak_context_node node = NULL;

 /* выполняем необходимые проверки */
  if(( oid = ak_context_node_get_context_oid( ctx, engine )) == NULL ) {
    ak_error_message_fmt( error = ak_error_get_value(), __func__ ,
                                           "incorrect oid extracting from given context pointer" );
    return NULL;
  }

 /* создаем контекст */
  if(( node = malloc( sizeof( struct context_node ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__,
                                          "wrong memory allocation for new context manager node" );
    return NULL;
  }

 /* разбираемся с описанием: выделяем память и копируем */
  len = 1 + ak_min( strlen( description ), 127 );
  if(( description == NULL ) || ( len == 1 )) node->description = NULL;
    else {
      if(( node->description = malloc( len )) != NULL ) {
        memset( node->description, 0, len );
        memcpy( node->description, description, len-1 );
      }
  }

 /* присваиваем остальные данные */
  node->ctx = ctx;
  node->handle = handle;
  node->oid = oid;
  node->status = node_is_equal;

 return node;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pointer указатель на элемент структуры управления контекстами.
    @return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_context_node_delete( ak_pointer pointer )
{
  ak_context_node node = ( ak_context_node ) pointer;

  if( node == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                       "wrong deleting a null pointer to context manager node" );
    return NULL;
  }

 /* уничтожаем описание */
  if( node->description != NULL ) free( node->description );
 /* уничтожаем контекст */
  if( node->oid->func.delete != NULL ) {
    if( node->ctx != NULL )
      node->ctx = (( ak_function_free_object *) node->oid->func.delete )( node->ctx );
  }
  node->handle = ak_error_wrong_handle;
  node->oid = NULL;
  node->status = node_undefined;
  free( node );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-context-node.c                                                                   */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                           ak_context_manager.c  */
/* ----------------------------------------------------------------------------------------------- */
