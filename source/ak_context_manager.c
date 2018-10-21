/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_context_manager.c                                                                      */
/*  - содержит реализацию функций для управления контекстами.                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
 #include <ak_sign.h>
 #include <ak_tools.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает oid из указателя на объект (контекст), тип которого задается
    параметром engine.
    @param ctx Контекст объетка.
    @param engine Тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @return Функция возвращает указатель на OID объекта.
    В случае возникновения ошибки возвращается NULL. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 static ak_oid ak_context_node_get_context_oid( ak_pointer ctx, ak_oid_engine engine )
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
    case omac_function:
                  oid = (( ak_omac ) ctx )->bkey.key.oid;
                  break;
    case block_cipher:
                  oid = (( ak_bckey ) ctx )->key.oid;
                  break;
    case sign_function:
                  oid = (( ak_signkey ) ctx )->key.oid;
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
/*                                   класс ak_context_node                                         */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает новый элемент структуры управления контекстами, заполняя его поля значениями,
    передаваемыми в качестве аргументов функции.

    @param ctx Контекст, который будет храниться в структуре управления контекстами.
    К моменту вызова функции контекст должен быть инфициализирован.
    @param id Идентификатор контекста, величина по которой пользовать может получить доступ
    к функциям, реализующим действия с контекстом.
    @param engine тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @param description пользовательское описание контекста
    @return Функция возвращает указатель на созданный элемент структуры управления контекстами.
    В случае возникновения ошибки возвращается NULL. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_context_node ak_context_node_new( ak_pointer ctx, ak_handle id, ak_oid_engine engine,
                                                                           const char *description )
{
  ak_oid oid = NULL;
  int error = ak_error_ok;
  ak_context_node node = NULL;

 /* выполняем необходимые проверки */
  if(( oid = ak_context_node_get_context_oid( ctx, engine )) == NULL ) {
    ak_error_message_fmt( error = ak_error_get_value(), __func__ ,
                                             "incorrect oid extracting for given context pointer" );
    return NULL;
  }

 /* создаем контекст */
  if(( node = malloc( sizeof( struct context_node ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__,
                                  "wrong memory allocation for new context manager node" );
    return NULL;
  }

 /* инициализируем буффер и присваиваем ему значение */
  if(( error = ak_buffer_create( &node->description )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong creation of internal buffer" );
    return ( node = ak_context_node_delete( node ));
  }

  if(( error = ak_buffer_set_str( &node->description, description )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong initialization of internal buffer" );
    return ( node = ak_context_node_delete( node ));
  }

 /* присваиваем остальные данные */
  node->ctx = ctx;
  node->id = id;
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

  ak_buffer_destroy( &node->description );

  if( node->oid->func.delete != NULL ) {
    if( node->ctx != NULL )
      node->ctx = (( ak_function_free_object *) node->oid->func.delete )( node->ctx );
  }
  node->id = ak_error_wrong_handle;
  node->oid = NULL;
  node->status = node_undefined;
  free( node );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Мьютекс для блокировки структуры управления контекстами */
#ifdef LIBAKRYPT_HAVE_PTHREAD
 static pthread_mutex_t ak_context_manager_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                    класс ak_context_manager                                     */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует структуру управления контекстами, присваивая ее полям значения,
    необходимые для обеспечения корректной работы.
    Начальное значение ожидаемого структурой количества контекстов, с которыми будет произодится
    работа, является внешним параметром библиотеки. Данное значение устанавливается
    в файле `libakrypt.conf` (см. раздел \ref construction_options).

    @param manager Указатель на структуру управления ключами
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_create( ak_context_manager manager )
{
  size_t idx = 0;
  int error = ak_error_ok;

  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                            "using a null pointer to context manager structure" );
 /* инициализируем генератор ключей */
#if defined(__unix__) || defined(__APPLE__)
  if(( error = ak_random_context_create_urandom( &manager->key_generator )) != ak_error_ok )
    return ak_error_message( error, __func__,
                            "wrong initialization of /dev/urandom for random number generation" );
#else
 #ifdef _WIN32
   if(( error = ak_random_context_create_winrtl( &manager->key_generator )) != ak_error_ok ) {
     ak_error_message( error, __func__,
                         "wrong initialization a random generator from default crypto provider" );
     ak_error_message( ak_error_ok, __func__, "trying to use lcg generator" );
     if(( error = ak_random_create_lcg( &manager->key_generator )) != ak_error_ok )
       return ak_error_message( error, __func__,
                                "wrong initialization of all types of random generators" );
   }
 #else
   #error ak_context_manager_create(): using a non defined path of compilation
 #endif
#endif

 /* инициализируем указатели контекстов */
  manager->size = ak_libakrypt_get_option("context_manager_size");

  if(( manager->array = malloc( manager->size*sizeof( ak_pointer ))) == NULL ) {
    ak_context_manager_destroy( manager );
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                            "wrong memory allocation for context manager nodes" );
  }
  for( idx = 0; idx < manager->size; idx++ ) manager->array[idx] = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция удаляет структуру управления контекстами, уничтожая данные, которыми она владеет.
    При выполнении функции:
    - уничтожаются контексты, хранящиеся в структуре,
    - уничтожается генератор псевдо-случайных чисел, использовавшийся для генерации
      ключевой информации.

    @param manager Указатель на структуру управления ключами
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_destroy( ak_context_manager manager )
{
  size_t idx = 0;
  int error = ak_error_ok;

  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                            "using a null pointer to context manager structure" );
  if( manager->array == NULL ) {
    ak_error_message( error = ak_error_undefined_value, __func__ ,
                                                   "cleaning context manager with empty memory" );
  } else {
          /* удаляем ключевые структуры */
           for( idx = 0; idx < manager->size; idx++ )
              if( manager->array[idx] != NULL )
                manager->array[idx] = ak_context_node_delete( manager->array[idx] );

           /* очищаем и уничтожаем память */
           memset( manager->array, 0, manager->size);
           free( manager->array );
           manager->array = NULL;
  }
  manager->size = 0;

 /* удаляем генератор ключей */
  if(( error = ak_random_context_destroy( &manager->key_generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using a null pointer to random key generator" );

 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                 теперь глобальный ak_context_manager                            */
/* ----------------------------------------------------------------------------------------------- */
 static ak_context_manager libakrypt_manager = NULL;

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create_context_manager( void )
{
  int error = ak_error_ok;

 /* блокируем доступ */
#ifdef LIBAKRYPT_HAVE_PTHREAD
  pthread_mutex_lock( &ak_context_manager_mutex );
#endif

 /* если уже создан, то выходим с уведомлением об ошибке */
  if( libakrypt_manager != NULL ) {
   #ifdef LIBAKRYPT_HAVE_PTHREAD
    pthread_mutex_unlock( &ak_context_manager_mutex );
   #endif
    return ak_error_message( ak_error_context_manager_usage, __func__,
                                                     "trying to create existing context manager" );
  }

  if(( libakrypt_manager = malloc( sizeof( struct context_manager ))) == NULL )
    ak_error_message( error = ak_error_out_of_memory, __func__,
                                                   "wrong memory allocation for context manager" );
  else {
         if(( error = ak_context_manager_create( libakrypt_manager )) != ak_error_ok )
           ak_error_message( error, __func__, "incorrect initialization of context manager" );
       }

 /* разблокируем доступ */
#ifdef LIBAKRYPT_HAVE_PTHREAD
  pthread_mutex_unlock( &ak_context_manager_mutex );
#endif

 if(( error == ak_error_ok ) && ( ak_log_get_level() >= ak_log_maximum ))
   ak_error_message( ak_error_ok, __func__ , "creation of context manager is Ok");

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_destroy_context_manager( void )
{
  int error = ak_error_ok;

 /* блокируем доступ */
#ifdef LIBAKRYPT_HAVE_PTHREAD
  pthread_mutex_lock( &ak_context_manager_mutex );
#endif

  if( libakrypt_manager == NULL ) {
   #ifdef LIBAKRYPT_HAVE_PTHREAD
    pthread_mutex_unlock( &ak_context_manager_mutex );
   #endif
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "destroying a null pointer to context manager" );
  }
  if(( error = ak_context_manager_destroy( libakrypt_manager )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroing of context manager" );

  free( libakrypt_manager );

 /* разблокируем доступ */
#ifdef LIBAKRYPT_HAVE_PTHREAD
  pthread_mutex_unlock( &ak_context_manager_mutex );
#endif

 if(( error == ak_error_ok ) && ( ak_log_get_level() >= ak_log_maximum ))
   ak_error_message( ak_error_ok, __func__ , "destroying of context manager is Ok");
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_context_manager ak_libakrypt_get_context_manager( void )
{
 ak_context_manager result = NULL;

 #ifdef LIBAKRYPT_HAVE_PTHREAD
  pthread_mutex_lock( &ak_context_manager_mutex );
 #endif

  result = libakrypt_manager;

#ifdef LIBAKRYPT_HAVE_PTHREAD
  pthread_mutex_unlock( &ak_context_manager_mutex );
#endif

  if( !result )
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to context manager" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-internal-context-node.c                                                        */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                           ak_context_manager.c  */
/* ----------------------------------------------------------------------------------------------- */
