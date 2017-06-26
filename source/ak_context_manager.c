/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 by Axel Kenzo, axelkenzo@mail.ru                                            */
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
/*   ak_context_manager.c                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_skey.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Мьютекс для блокировки структуры управления контекстами */
 static pthread_mutex_t ak_context_manager_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует структуру управления контекстами, присваивая ее полям значения,
    необходимые для обеспечения корректной работы.
    Начальное значение ожидаемого структурой количества контекстов, с которыми будет произодится
    работа, является внешним параметром библиотеки. Данное значение устанавливается
    в файле \ref libakrypt.conf

    Аргументом функции является генератор псевдо-случайных чисел, который будет использован
    для выработки новых (создаваемых библиотекой в процессе работы) ключевых значений. После
    инициализации владение генератором переходит структуре управления ключами.

    @param manager Указатель на структуру управления ключами
    @param generator Указатель на генератор псевдо-случайных чисел
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_create( ak_context_manager manager, ak_random generator )
{
  size_t idx = 0;
  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                            "using a null pointer to context manager structure" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                              "using a null pointer to random number generator" );

 /* выделяем память и инициализируем указатели */
  manager->size = 4;
  ak_error_message( ak_error_ok, __func__ , "TODO: load manager->size value from /etc/libakrypt.conf");

  if(( manager->array = malloc( manager->size*sizeof( ak_pointer ))) == NULL ) {
    generator = ak_random_delete( generator );
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                            "wrong memory allocation for context manager nodes" );
  }
  for( idx = 0; idx < manager->size; idx++ ) manager->array[idx] = NULL;
  manager->generator = generator;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выделяет дополнительную память под массив хранения контекстов.
    При выделении памяти производится перенос содержащихся в массиве указателей
    (элементов структуры управления контекстами) в новую область памяти.
    Старая область памяти уничтожается.

    При выделении памяти размер новой области увеличивается в два раза, по сравнению с предыдущим
    объемом, то есть происходит двукратное увеличение. Максимальное число
    хранимых в структуре управления контекстов является внешним параметром библиотеки.
    Данное значение устанавливается в файле \ref libakrypt.conf

    @param manager Указатель на структуру управления ключами
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_morealloc( ak_context_manager manager )
{
  ak_context_node *newarray = NULL;
  size_t idx = 0, newsize = (manager->size << 1);

  if( newsize > 4096 ) return ak_error_message( ak_error_context_manager_max_size, __func__,
                                     "current size of context manager exceeds permissible bounds" );
  ak_error_message( ak_error_ok, __func__ ,
                              "TODO: load maximum of manager->size value from /etc/libakrypt.conf");

  if(( newarray = malloc( newsize*sizeof( ak_pointer ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                              "wrong memory allocation for context manager nodes" );

 /* копируем данные и очищаем память */
  for( idx = 0; idx < manager->size; idx++ ) newarray[idx] = manager->array[idx];
  for( idx = manager->size; idx < newsize; idx++ ) newarray[idx] = NULL;

  memset( manager->array, 0, manager->size*sizeof( ak_pointer ));
  free( manager->array );
  manager->array = newarray;
  manager->size = newsize;

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

 /* удаляем генератор псевдо-случайных чисел */
  if( manager->generator == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                              "using a null pointer to random number generator" );
   else manager->generator = ak_random_delete( manager->generator );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция находит первый равный NULL адрес элемента структуры и
    помещает по этому адресу новый элемент. В случае, если текущей объем памяти недостаточен для
    размещения нового элемента, происходит выделение нового фрагмента памяти.

    @param manager Указатель на структуру управления ключами
    @param ctx Контекст, который будет храниться в структуре управленияя контекстами
    @param engine тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @param description пользовательское описание контекста
    @param func функция освобождения памяти, занимаемой контекстом
    @return Функция возвращает идентификатор созданного контекста. В случае
    возникновения ошибки возвращается значение \ref ak_key_wrong. Код ошибки может быть получен
    с помощью вызова функции ak_error_get_value().                                                 */
/* ----------------------------------------------------------------------------------------------- */
 ak_key ak_context_manager_add_node( ak_context_manager manager, ak_pointer ctx,
                       ak_oid_engine engine, ak_buffer description, ak_function_free_object *func )
{
  size_t idx = 0;
  ak_context_node node = NULL;

  if( manager == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to context manager" );
    return ak_error_wrong_key;
  }

 /* блокируем доступ к структуре управления контекстами */
  pthread_mutex_lock( &ak_context_manager_mutex );

 /* ищем свободный адрес */
  for( idx = 0; idx < manager->size; idx++ ) {
     if( manager->array[idx] == NULL ) break;
  }
  if( idx == manager->size ) {
    if( ak_context_manager_morealloc( manager ) != ak_error_ok ) {
      ak_error_message( ak_error_get_value(), __func__, "wrong creation of context descriptor" );
      pthread_mutex_unlock( &ak_context_manager_mutex );
      return ak_error_wrong_key;
    }
  }

 /* адрес найден, теперь размещаем контекст */
  if(( node = ak_context_node_new( ctx, idx, engine, description, func )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong creation of context manager node" );
    pthread_mutex_unlock( &ak_context_manager_mutex );
    return ak_error_wrong_key;
  }
  manager->array[idx] = node;
  pthread_mutex_unlock( &ak_context_manager_mutex );

 return idx;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_delete_node( ak_context_manager manager, ak_key idx )
{
  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to context manager" );
  if(( idx < 0 ) || ( idx >= manager->size ))
    return ak_error_message( ak_error_wrong_key, __func__,
                                                      "using an unexpected value of secret key" );

 /* блокируем доступ и изменяем поля структуры управления контекстами */
  pthread_mutex_lock( &ak_context_manager_mutex );
  manager->array[idx] = ak_context_node_delete( manager->array[idx] );
  pthread_mutex_unlock( &ak_context_manager_mutex );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает новый элемент структуры управления контекстами, заполняя его поля значениями,
    передаваемыми в качестве аргументов функции.

    @param ctx Контекст, который будет храниться в структуре управленияя контекстами
    @param id Идентификатор контекста, величина по которой пользовать может получить доступ
    к функциям, реализующим действия с контекстом.
    @param engine тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @param description пользовательское описание контекста
    @param func функция освоюождения памяти, занимаемой контекстом
    @return Функция возвращает указатель на созданный элемент структуры управления контекстами.
    В случае возникновения ошибки возвращается NULL. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_context_node ak_context_node_new( ak_pointer ctx, ak_key id, ak_oid_engine engine,
                                              ak_buffer description, ak_function_free_object *func )
{
  ak_context_node node = NULL;

 /* минимальные проверки */
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to context" );
    return NULL;
  }
  if( func == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                         "using a null pointer to context free function" );
    return NULL;
  }
 /* создаем контекст */
  if(( node = malloc( sizeof( struct context_node ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__,
                                  "wrong memory allocation for new context manager node" );
    return NULL;
  }

 /* присваиваем данные */
  node->ctx = ctx;
  node->id = id;
  node->engine = engine;
  node->description = description;
  node->free = func;
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

  if( node->description != NULL ) node->description = ak_buffer_delete( node->description );
  if( node->free != NULL ) {
    if( node->ctx != NULL ) node->ctx = node->free( node->ctx );
    node->free = NULL;
  }
  node->id = ak_error_wrong_key;
  node->status = node_undefined;
  node->engine = undefined_engine;
  free( node );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Глобальная структура для хранения и обработки ключевых контекстов */
 static struct context_manager libakrypt_context_manager;

/* ----------------------------------------------------------------------------------------------- */
/*! @return Функция возвращает указатель на глобальную структуру управоения контекстами */
 ak_context_manager ak_libakrypt_get_context_manager( void )
{
  return &libakrypt_context_manager;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create_context_manager( void )
{
  ak_random generator = NULL;

#ifdef __linux__
  if(( generator = ak_random_new_file("/dev/random")) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                             "wrong initialization of /dev/random for random number generation" );
#else
 #ifdef _WIN32
   if(( generator = ak_random_new_winrtl( )) == NULL )
     return ak_error_message( ak_error_get_value(),
                           __func__, "wrong initialization of crypto provider random generator" );
 #else
  if(( generator = ak_random_new_lcg()) == NULL )
    return ak_error_message( ak_error_get_value(),
                                __func__, "wrong initialization of linear congruence generator" );
 #endif
#endif

 return ak_context_manager_create( &libakrypt_context_manager, generator );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_destroy_context_manager( void )
{
  return ak_context_manager_destroy( &libakrypt_context_manager );
}

/* ----------------------------------------------------------------------------------------------- */
/*          реализация интерфейсных функций для пользователя, использующих context_manager         */
/* ----------------------------------------------------------------------------------------------- */
/*! @param password Буффер, содержащий в себе значение пароля, из которого вырабатываемтся ключ
    @param description Пользовательское описание ключа (буффер, содержащий строку символов).
    После создания ключа владение буффером с пользовательским описанием переход
    к дескриптору ключа.

    @return Функция возвращает дескриптор созданного ключа. Если создание ключа произошло с ошибкой,
    то возвращается отрицательное значение \ref ak_error_wrong_key. Код ошибки может быть получен
    с помощью вызова функции ak_error_get_value()                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_key ak_key_new_magma_password( ak_buffer password, ak_buffer description )
{
  ak_bckey bkey = NULL;
  ak_key key = ak_error_wrong_key;

  if( password == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to password buffer" );
    return ak_error_wrong_key;
  }
  if( password->data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to password data" );
    return ak_error_wrong_key;
  }
  if( password->size == 0 ) {
    ak_error_message( ak_error_zero_length, __func__, "using a password with zero length" );
    return ak_error_wrong_key;
  }
  if(( bkey = ak_bckey_new_magma_password( password->data, strlen( password->data ))) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong creation a block cipher key" );
    return ak_error_wrong_key;
  }

  if(( key = ak_context_manager_add_node( &libakrypt_context_manager, bkey, block_cipher,
                                   description, ak_bckey_delete )) == ak_error_wrong_key ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong initialization of block cipher key");
    bkey = ak_bckey_delete( bkey );
  }
 return key;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param description Пользовательское описание ключа (буффер, содержащий строку символов).
    После создания ключа владение буффером с пользовательским описанием переход
    к дескриптору ключа.

    @return Функция возвращает дескриптор созданного ключа. Если создание ключа произошло с ошибкой,
    то возвращается отрицательное значение \ref ak_error_wrong_key. Код ошибки может быть получен
    с помощью вызова функции ak_error_get_value()                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_key ak_key_new_magma_random( ak_buffer description )
{
  ak_bckey bkey = NULL;
  ak_key key = ak_error_wrong_key;

  if( libakrypt_context_manager.generator == NULL ) {
    ak_error_message( ak_error_undefined_value, __func__ , "using non initialized context managment");
    return ak_error_wrong_key;
  }
  if(( bkey = ak_bckey_new_magma_random( libakrypt_context_manager.generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong creation a block cipher key" );
    return ak_error_wrong_key;
  }
  if(( key = ak_context_manager_add_node( &libakrypt_context_manager, bkey, block_cipher,
                                      description, ak_bckey_delete )) == ak_error_wrong_key ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong initialization of block cipher key");
    bkey = ak_bckey_delete( bkey );
  }
 return key;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка корректности дескриптогра ключа

    Функция проверяет, что внутренний массив контекстов содержит в себе отличный от NULL контекст
    с заданным значеним дескриптора ключа. Функция не экспортируется.

    @param key Дескриптор ключа.
    @return В случае ошибки возвращается ее код. В случае успеха, возвращается значение
    \ref ak_error_ok                                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_key_check( ak_key key )
{
  if(( key < 0 ) || ( key >= libakrypt_context_manager.size ))
    return ak_error_message( ak_error_wrong_key, __func__, "invalid key index" );
  if( libakrypt_context_manager.array[key] == NULL )
    return ak_error_message( ak_error_null_pointer, __func__, "using undefined key context" );
  if( libakrypt_context_manager.array[key]->ctx == NULL )
    return ak_error_message( ak_error_null_pointer, __func__, "using undefined key" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка корректности криптографического механизма для заданного дескриптора ключа

    Функция проверяет, что заданный дескриптор ключа соответствует заданному
    криптографическому алгоритму
    @param key Дескриптор ключа.
    @return В случае ошибки возвращается \ref ak_error_oid_engine.
    В случае успеха, возвращается значение \ref ak_error_ok                                        */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_key_check_engine( ak_key key, ak_oid_engine engine )
{
  if( libakrypt_context_manager.array[key]->engine != engine )
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong engine for given key" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param key дескриптор ключа, для которого возвращается пользовательское описание
    @return Функция возвращает указатель на буффер с пользовательским описанием ключа.
    Если дескриптор ключа задан не верно, то будет возвращено значение NULL. Код возникшей
    ошибки может быть получен с помощью вызова функции ak_error_get_value()                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_key_get_description( ak_key key )
{
  int error = ak_key_check( key );
  if( error != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong key descriptor");
    return NULL;
  }
 return libakrypt_context_manager.array[key]->description;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_key_xcrypt( ak_key key, ak_pointer in, ak_pointer out, size_t size, ak_pointer iv )
{
  int error = ak_key_check( key );
  if( error != ak_error_ok ) return ak_error_message( error, __func__, "wrong key descriptor");

  if(( error = ak_key_check_engine( key, block_cipher )) != ak_error_ok )
    return ak_error_message( error, __func__, "using non block cipher key descriptor");

 /* модифицируем статус ключа */
  libakrypt_context_manager.array[key]->status = node_modified;
 /* и только потом запускаем криптографическое преобразование */
  if(( error = ak_bckey_xcrypt(( ak_bckey )libakrypt_context_manager.array[key]->ctx,
                                                             in, out, size, iv )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid result of xcrypt operation" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_key_xcrypt_update( ak_key key, ak_pointer in, ak_pointer out, size_t size )
{
  int error = ak_key_check( key );
  if( error != ak_error_ok ) return ak_error_message( error, __func__, "wrong key descriptor");

  if(( error = ak_key_check_engine( key, block_cipher )) != ak_error_ok )
    return ak_error_message( error, __func__, "using non block cipher key descriptor");

 /* модифицируем статус ключа */
  libakrypt_context_manager.array[key]->status = node_modified;
 /* и только потом запускаем криптографическое преобразование */
  if(( error = ak_bckey_xcrypt_update(( ak_bckey )libakrypt_context_manager.array[key]->ctx,
                                                                   in, out, size )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid result of xcrypt operation" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-context-manager.c                                                             */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                           ak_context_manager.c  */
/* ----------------------------------------------------------------------------------------------- */
