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
/*! Глобальная структура для хранения и обработки ключевых контекстов */
// static struct context_manager ctx_manager;

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

  if(( manager->array = malloc( manager->size*sizeof( ak_pointer ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                              "wrong memory allocation for key conext pointers" );
  for( idx = 0; idx < manager->size; idx++ ) manager->array[idx] = NULL;

 /* вырабатываем маску */
  if(( manager->imask = ak_random_uint64( manager->generator = generator )) == 0 )
    manager->imask = 0xfe1305da97c3e98dL;
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
  int error = ak_error_ok;
  ak_context_node *newarray = NULL;
  size_t idx = 0, newsize = (manager->size << 1);

  if( newsize > 4096 ) return ak_error_message( ak_error_context_manager_max_size, __func__,
                                     "current size of context manager exceeds permissible bounds" );
  ak_error_message( ak_error_ok, __func__ ,
                              "TODO: load maximum of manager->size value from /etc/libakrypt.conf");

  if(( newarray = malloc( newsize*sizeof( ak_pointer ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                "wrong memory allocation for key conext pointers" );

 /* копируем данные и очищаем память */
  for( idx = 0; idx < manager->size; idx++ ) newarray[idx] = manager->array[idx];
  for( idx = manager->size; idx < newsize; idx++ ) newarray[idx] = NULL;

  if(( error = ak_random_ptr( manager->generator,
                        manager->array, manager->size*sizeof( ak_pointer ))) != ak_error_ok )
                             ak_error_message( error, __func__ , "wrong generation a random data" );
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
           if(( error = ak_random_ptr( manager->generator,
                          manager->array, manager->size*sizeof( ak_pointer ))) != ak_error_ok )
                           ak_error_message( error, __func__ , "wrong generation a random data" );
           free( manager->array );
           manager->array = NULL;
  }
  manager->size = 0;

 /* удаляем генератор псевдо-случайных чисел */
  if( manager->generator == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                              "using a null pointer to random number generator" );
   else manager->generator = ak_random_delete( manager->generator );
  manager->imask = 0;

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
    @return Функция возвращает указатель на сохданный элемент структуры управления контекстами.
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
  node->id = ak_key_descriptor_wrong;
  node->status = node_undefined;
  node->engine = undefined_engine;
  free( node );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                           ak_context_manager.c  */
/* ----------------------------------------------------------------------------------------------- */
