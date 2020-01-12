/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_skey.h                                                                                 */
/*  - содержит реализации функций, предназначенных для хранения и обработки ключевой информации.   */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hmac.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_TIME_H
 #include <time.h>
#else
 #error Library cannot be compiled without time.h header
#endif
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

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция выделяет массив памяти, достаточный для размещения секретного ключа и
    его маски (размер выделяемой памяти в точности равен удвленному разхмеру секретного ключа).
    Выделение памяти собственно под контекст секретного ключа не происходит.

    \param skey Контекст секретного ключа
    \param size Размер секретного ключа (в октетах)
    \param policy Метод выделения памяти.
    \return В случае успеха возвращается значение \ref ak_error_ok. В случае возникновения
     ошибки возвращается ее код.                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_alloc_memory( ak_skey skey, size_t size, memory_allocation_policy_t policy )
{
#ifdef LIBAKRYPT_HAVE_STDALIGN_H
  alignas(16)
#endif
  ak_uint8 *ptr = NULL;
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                    "using a null pointer to secret key context" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                              "using a zero length for key size" );
  if( size > ((size_t)-1 ) >> 1 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                                "using a very huge length value" );
  switch( policy ) {
    case malloc_policy:
     /* выделяем новую память (под ключ и его маску) */
      if(( ptr = ak_libakrypt_aligned_malloc( size << 1 )) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__,
                                                    "incorrect memory allocation for key buffer" );
     /* освобождаем и очищаем память */
      if( skey->key != NULL ) ak_skey_context_free_memory( skey );
      memset( ptr, 0, size << 1 );
      skey->key = ptr;
      break;

    default:
      return ak_error_message( ak_error_undefined_value, __func__,
                                                            "using unexpected allocation policy" );
  }
  skey->policy = policy;
  skey->key_size = size;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция освобождает память, выделеннную функцией ak_skey_context_alloc_memory().
    Перед освобождением памяти производится ее очистка.
    \param skey Контекст секретного ключа
    \return В случае успеха возвращается значение \ref ak_error_ok. В случае возникновения
     ошибки возвращается ее код.                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_free_memory( ak_skey skey )
{
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                    "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_ok;

 /* очищаем память перед ее удалением */
  if( skey->generator.random != NULL ) {
     if( ak_ptr_context_wipe( skey->key, skey->key_size << 1, &skey->generator ) != ak_error_ok )
       ak_error_message( ak_error_get_value(), __func__, "incorrect wiping a key buffer" );
  } else {
     memset( skey->key, 0, skey->key_size << 1 );
     ak_error_message( ak_error_undefined_function, __func__,
                                          "use standard memset() function for key buffer wiping" );
    }
 /* теперь освобождаем */
  switch( skey->policy ) {
    case malloc_policy:
      skey->policy = undefined_policy;
      free( skey->key );
      break;

    default:
      return ak_error_message( ak_error_undefined_value, __func__,
                                    "using secret key conetxt with unexpected allocation policy" );
  }
 return  ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Выработанный функцией номер является уникальным (в рамках библиотеки) и однозначно идентифицирует
    секретный ключ. Данный идентификатор может сохраняться вместе с ключом.

    @param skey контекст секретного ключа, для клоторого вырабатывается уникальный номер
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае, возвращается
    номер ошибки.                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_unique_number( ak_skey skey )
{
  time_t tm = 0;
  size_t len = 0;
  struct hash ctx;
  ak_uint8 out[64];
  ak_uint64 rvalue = 0;
  int error = ak_error_ok;
  const char *version =  ak_libakrypt_version();

 /* стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if(( error = ak_hash_context_create_streebog256( &ctx )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong creation of hash function context" );

  memset( out, 0, sizeof( out ));

 /* заполняем стандартное начало вектора: версия */
  if(( len = strlen( version )) > sizeof( out )) goto run_point;
  memcpy( out, version, len ); /* сначала версия библиотеки */

 /* заполняем стандартное начало вектора: текущее время */
  if( len + sizeof( time_t ) > sizeof( out )) goto run_point;
  tm = time( NULL );
  memcpy( out+len, &tm, sizeof( tm )); /* потом время генерации номера ключа */
  len += sizeof( time_t );

 /* уникальное для каждого вызова функции значение */
  if( len + sizeof( ak_uint64 ) > sizeof( out )) goto run_point;
  rvalue = ak_random_value();
  memcpy( out+len, &rvalue, sizeof( ak_uint64 ));
  len += sizeof( ak_uint64 );

  if( len < sizeof( out )) { /* используем генератор, отличный от генератора масок */
    struct random generator;
    if( ak_random_context_create_lcg( &generator ) == ak_error_ok ) {
      ak_random_context_random( &generator, out+len, (ssize_t)( sizeof( out ) - len )); /* добавляем мусор */
      ak_random_context_destroy( &generator );
    }
  }

 /* вычисляем номер и очищаем память */
  run_point: if(( error = ak_hash_context_ptr( &ctx, out, sizeof( out ),
                                            skey->number, sizeof( skey->number ))) != ak_error_ok )
               ak_error_message( error, __func__, "incorrect creation an unique number" );
  ak_hash_context_destroy( &ctx );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует поля структуры, выделяя для этого необходимую память. Всем полям
    присваиваются значения по-умолчанию.

    После создания, указатели на методы cекретного ключа инициализируются для
    работы с аддитивной по модулю 2 маской (наложение маски с помощью операции `xor`).
    В случае необходимости использования другого способа маскирования,
    функции должны переопределяться в производящих функциях для конктерного типа секретного ключа.

    \note Остаются неопределенными поля `data`, `resource` и `oid`.
    Перечисленные поля и методы также должны определяться производящими функциями.

    @param skey Контекст секретного ключа. Память под контекст должна быть выделена заранее.
    @param size Размер секретного ключа в байтах
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_create( ak_skey skey, size_t size )
{
  int error = ak_error_ok;
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                              "using a zero length for key size" );
 /* Инициализируем данные базовыми значениями */
  skey->key = NULL;
  if(( error = ak_skey_context_alloc_memory( skey, size, malloc_policy )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong allocation memory of internal secret key buffer" );
    ak_skey_context_destroy( skey );
    return error;
  }

  skey->icode = 0; /* контрольная сумма ключа не задана */
  skey->data = NULL; /* внутренние данные ключа не определены */
  memset( &(skey->resource), 0, sizeof( struct resource )); /* ресурс ключа не определен */

 /* инициализируем генератор масок */
  if(( error = ak_random_context_create_lcg( &skey->generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of random generator" );
    ak_skey_context_destroy( skey );
    return error;
  }

 /* номер ключа генерится случайным образом; изменяется позднее, например,
                                                           при считывании с файлового носителя */
  if(( error = ak_skey_context_set_unique_number( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid creation of key number" );
    ak_skey_context_destroy( skey );
    return error;
  }

  /* OID ключа устанавливается производящей функцией */
  skey->oid = NULL;
  /* После создания ключа все его флаги не определены */
  skey->flags = ak_key_flag_undefined;
 /* В заключение определяем указатели на методы.
    по умолчанию используются механизмы для работы с аддитивной по модулю 2 маской.

    Внимание: указатели на функции, отличные от данных, должны устанавливаться при создании
    конкретного типа ключа, например, конкретного алгоритма блочного шифрования */
  skey->set_mask = ak_skey_context_set_mask_xor;
  skey->unmask = ak_skey_context_unmask_xor;
  skey->set_icode = ak_skey_context_set_icode_xor;
  skey->check_icode = ak_skey_context_check_icode_xor;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция удаляет все выделенную память и уничтожает хранившиеся в ней значения.

    @param skey Контекст секретного ключа.
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_destroy( ak_skey skey )
{
  int error = ak_error_ok;
  ak_uint8 data[sizeof( struct skey )];

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                         "destroying null pointer to secret key" );
  if(( error = ak_skey_context_free_memory( skey )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect freeing of internal key buffer" );

  memset( data, 0, sizeof( skey ));
  if( skey->generator.random != NULL )
    if(( error = ak_random_context_random( &skey->generator, data, sizeof( data ))) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect generation of random buffer" );

  ak_random_context_destroy( &skey->generator );
  if( skey->data != NULL ) {
   /* при установленном флаге память не очищаем */
    if( !((skey->flags)&ak_key_flag_data_not_free )) free( skey->data );
  }
  skey->oid = NULL;
  skey->flags = ak_key_flag_undefined;

 /* замещаем ключевый данные произвольным мусором */
  memcpy( skey, data, sizeof( data ));
  memset( data, 0, sizeof( data ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает случайный вектор \f$ v \f$ длины, совпадающей с длиной ключа,
    и заменяет значение ключа \f$ k \f$ на величину \f$ k \oplus v \f$.
    Значение вектора \f$ v \f$ сохраняется в контексте секретного ключа.

    @param skey Контекст секретного ключа.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_mask_xor( ak_skey skey )
{
  size_t idx = 0, jdx = 0;
  int error = ak_error_ok;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
 /* проверяем, установлена ли маска ранее */
  if((( skey->flags)&ak_key_flag_set_mask ) == 0 ) {
    /* создаем маску*/
     if(( error = ak_random_context_random( &skey->generator,
                             skey->key+skey->key_size, (ssize_t)skey->key_size )) != ak_error_ok )
       return ak_error_message( error, __func__ ,
                                                 "wrong generation a random mask for key buffer" );
    /* накладываем маску на ключ */
     jdx = skey->key_size;
     for( idx = 0; idx < skey->key_size; idx++, jdx++ ) skey->key[idx] ^= skey->key[jdx];
    /* меняем значение флага */
     skey->flags |= ak_key_flag_set_mask;

  } else { /* если маска уже установлена, то мы сменяем ее на новую */
          ak_uint8 newmask[64];
          size_t jdx = 0, offset = 0,
              blocks = skey->key_size >> 6, /* работаем с блоком длины 64 байта */
                tail = skey->key_size - ( blocks << 6 );

         /* сначала обрабатываем полные блоки */
          for( jdx = 0; jdx < blocks; jdx++, offset += sizeof( newmask )) {
             if(( error = ak_random_context_random( &skey->generator,
                                                     newmask, sizeof( newmask ))) != ak_error_ok )
               return ak_error_message( error, __func__ ,
                                                 "wrong generation a random mask for key buffer" );
             for( idx = 0; idx < 64; idx++ ) {
                  skey->key[offset+idx] ^= newmask[idx];
                  skey->key[offset+idx+skey->key_size] ^= newmask[idx];
             }
          }
         /* потом обрабатываем хвост */
          if( tail ) {
            if(( error = ak_random_context_random( &skey->generator,
                                                       newmask, (ssize_t)tail )) != ak_error_ok )
              return ak_error_message( error, __func__ ,
                                                  "wrong random mask generation for key buffer" );
            for( idx = 0; idx < tail; idx++ ) {
               skey->key[offset+idx] ^= newmask[idx];
               skey->key[offset+idx+skey->key_size] ^= newmask[idx];
            }
          }
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция снимает наложенную ранее маску и оставляет значение ключа в его истинном виде.
    @param skey Контекст секретного ключа.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_unmask_xor( ak_skey skey )
{
  size_t idx = 0, jdx = 0;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
 /* проверяем, установлена ли маска ранее */
  if( (( skey->flags)&ak_key_flag_set_mask ) == 0 ) return ak_error_ok;

 /* снимаем маску с ключа (побайтно) */
  jdx = skey->key_size;
  for( idx = 0; idx < skey->key_size; idx++, jdx++ ) {
     skey->key[idx] ^= skey->key[jdx];
     skey->key[jdx] = 0;
  }

 /* меняем значение флага */
  skey->flags ^= ak_key_flag_set_mask;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Контекст секретного ключа.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_icode_xor( ak_skey skey )
{
  ak_uint32 x = 0;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
 /* в силу аддитивности контрольной суммы,
    мы вычисляем результат последоватлеьно для ключа, а потом для его маски */
  ak_ptr_fletcher32_xor( skey->key, skey->key_size, &x );
  ak_ptr_fletcher32_xor( skey->key+skey->key_size, skey->key_size, &skey->icode );
  skey->icode ^=x;

 /* устанавливаем флаг */
  skey->flags |= ak_key_flag_set_icode;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Контекст секретного ключа.

    @return В случае совпадения контрольной суммы ключа функция возвращает истину (\ref ak_true).
    В противном случае, возвращается ложь (\ref ak_false).                                         */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_skey_context_check_icode_xor( ak_skey skey )
{
  ak_uint32 x = 0, y = 0;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) { ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
    return ak_false;
  }
  if( skey->key == NULL ) { ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
    return ak_false;
  }
  if( skey->key_size == 0 ) { ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
    return ak_false;
  }

 /* в силу аддитивности контрольной суммы,
    мы вычисляем результат последоватлеьно для ключа, а потом для его маски */
  ak_ptr_fletcher32_xor( skey->key, skey->key_size, &x );
  ak_ptr_fletcher32_xor( skey->key+skey->key_size, skey->key_size, &y );

  if( skey->icode == ( x^y )) return ak_true;
    else return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Присвоение времени происходит следующим образом. Если `not_before` равно нулю, то
    устанавливается текущее время. Если `not_after` равно нулю или меньше, чем `not_before`,
    то временной интервал действия ключа устанавливается равным 365 дней.

    \param skey Контекст секретного ключа.
    \param not_before Время, начиная с которого ключ действителен. Значение, равное нулю,
    означает, что будет установлено текущее время.
    \param not_after Время, начиная с которого ключ недействителен.
    \return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_resource_time( ak_skey skey, time_t not_before, time_t not_after )
{
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* устанавливаем временной интервал */
  if( not_before == 0 )
 #ifdef LIBAKRYPT_HAVE_TIME_H
  skey->resource.time.not_before = time( NULL );
 #else
  skey->resource.time.not_before = 0;
 #endif
    else skey->resource.time.not_before = not_before;
  if( not_after == 0 ) skey->resource.time.not_after = skey->resource.time.not_before + 31536000;
    else {
      if( not_after > skey->resource.time.not_before ) skey->resource.time.not_after = not_after;
        else skey->resource.time.not_after = skey->resource.time.not_before + 31536000;
    }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Счетчику ресурса присваивается значение, определенное заданной опцией библиотеки.

    Присвоение времени происходит следующим образом. Если `not_before` равно нулю, то
    устанавливается текущее время. Если `not_after` равно нулю или меньше, чем `not_before`,
    то временной интервал действия ключа устанавливается равным 365 дней.

    \param skey Контекст секретного ключа.
    \param type Тип присваиваемого ресурса.
    \param option Строка с именем опции, значение которой присваивается.
    \param not_before Время, начиная с которого ключ действителен. Значение, равное нулю,
    означает, что будет установлено текущее время.
    \param not_after Время, начиная с которого ключ недействителен.
    \return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_resource( ak_skey skey, counter_resource_t type, const char *option,
                                                               time_t not_before, time_t not_after )
{
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( option == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using a null pointer to option name" );
  ak_skey_context_set_resource_time( skey, not_before, not_after );
  switch( skey->resource.value.type = type ) {
    case block_counter_resource:
    case key_using_resource:
      if(( skey->resource.value.counter =
                  ak_libakrypt_get_option( option )) != ak_error_wrong_option ) return ak_error_ok;
        else return ak_error_wrong_option;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             функции установки ключевой информации                               */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу заданное пользователем значение.
    Данное значение копируется во внутреннюю память контекста секретного ключа, тем самым,
    происходит размножение ключевой информации.

    Основная область применения функции заключается в реализации тестовых примеров, для которых
    значение ключа является заранее известной константой. Другим вариантом использования данной функции
    явлются ситуации, в которых ключевое значения является результатом некоторого
    криптографического преобразования.

    \param skey Контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    \param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    \param size Размер данных, на которые указывает `ptr` (размер в байтах).
    Если величина `size` меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только `size` байт (остальные заполняются нулями). Если `size` больше, чем количество выделенной памяти
    под ключ, то копируются только младшие байты, в количестве `key.size` байт.

    \return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_key( ak_skey skey, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using a null pointer to secret key data" );
 /* присваиваем ключ */
  if( size != skey->key_size )
    if(( error = ak_skey_context_alloc_memory( skey, size, skey->policy )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect allocation new secret key buffer" );

  memcpy( skey->key, ptr, size );            /* копируем данные */
  memset( skey->key+size, 0, size ); /* обнуляем массив масок */

 /* очищаем флаг начальной инициализации */
  skey->flags &= (0xFFFFFFFFFFFFFFFFLL ^ ak_key_flag_set_mask );

 /* маскируем ключ и вычисляем контрольную сумму */
  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );

  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_key_flag_set_key;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу случайное (псевдо-случайное) значение, размер которого определяется
    размером секретного ключа. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    @param skey Контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param generator Контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_key_random( ak_skey skey, ak_random generator )
{
  int error = ak_error_ok;

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using a null pointer to random number generator" );
 /* присваиваем случайный ключ и случайную маску
    тем самым точное значение ключа ни как не фигурирует */
  if(( error = ak_random_context_random( generator, skey->key,
                                              ( ssize_t )( skey->key_size << 1 ))) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a secret key" );

 /* меняем значение флага маски на установленное */
  skey->flags |= ak_key_flag_set_mask;
  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                 __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_key_flag_set_key;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи
    алгоритма PBKDF2, описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    Количество итераций алгоритма PBKDF2 определяется опцией библиотеки `pbkdf2_iteration_count`,
    значение которой может быть опредедено с помощью вызова функции ak_libakrypt_get_option().

    @param skey Контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован функцией ak_skey_context_create().
    @param pass Пароль, представленный в виде строки символов.
    @param pass_size Длина пароля в октетах
    @param salt Случайный вектор, представленный в виде строки символов.
    @param salt_size Длина случайного вектора в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_key_from_password( ak_skey skey,
                                                const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                              "using a null pointer to password" );
  if( !pass_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                             "using a password with zero length" );
 /* присваиваем буффер и маскируем его */
  if(( error = ak_hmac_context_pbkdf2_streebog512( pass, pass_size, salt, salt_size,
                   (const size_t) ak_libakrypt_get_option("pbkdf2_iteration_count"),
                                                     skey->key_size, skey->key )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a secret key data" );
  memset( skey->key+skey->key_size, 0, skey->key_size ); /* обнуляем массив масок */

 /* очищаем флаг начальной инициализации */
  skey->flags &= (0xFFFFFFFFFFFFFFFFLL ^ ak_key_flag_set_mask );

 /* маскируем ключ и вычисляем контрольную сумму */
  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );

  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_key_flag_set_key;
 return error;
}


#ifdef LIBAKRYPT_HAVE_DEBUG_FUNCTIONS
/* ----------------------------------------------------------------------------------------------- */
/*! Данная функция используется для отладки работы механизмов доступа и обработки ключевой
    информации. Функция включается в состав библиотеки только в случае сборки тестовых примеров.

    @param skey Контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param fp Файл, в который выводится информация.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_print_to_file( ak_skey skey, FILE *fp )
{
  size_t i = 0;
  char *bc = "block counter", *rc = "key usage counter";

 /* информация о ключе */
  fprintf( fp, "key buffer size: %u bytes\nkey context size: %u bytes\n",
                                (unsigned int)skey->key_size, (unsigned int)sizeof( struct skey ));
  if(( skey->oid != NULL ) && ( skey->oid->names[0] != NULL ))
    fprintf( fp, "key info: %s (OID: %s, engine: %s, mode: %s)\n",
        skey->oid->names[0], skey->oid->id, ak_libakrypt_get_engine_name( skey->oid->engine ),
                                                    ak_libakrypt_get_mode_name( skey->oid->mode ));
   else fprintf( fp, "key info: unidentified\n");

  fprintf( fp, "unique number:\n\t");
  for( i = 0; i < sizeof( skey->number ); i++ ) fprintf( fp, "%02X", skey->number[i] );
  fprintf( fp, "\n");

  if( skey->key != NULL ) {
    fprintf( fp, "fields:\n key:\t");
    for( i = 0; i < skey->key_size; i++ ) fprintf( fp, "%02X", skey->key[i] );
    fprintf( fp, "\n mask:\t");
    for( i = 0; i < skey->key_size; i++ ) fprintf( fp, "%02X", skey->key[i+skey->key_size] );
  } else fprintf( fp, "secret key buffer is undefined\n");
  fprintf( fp, "\n icode:\t%08X", skey->icode );
  if( skey->check_icode( skey ) == ak_true ) printf(" (Ok)\n");
   else printf(" (Wrong)\n");

  skey->unmask( skey ); /* снимаем маску */
  fprintf( fp, " real:\t");
  for( i = 0; i < skey->key_size; i++ ) fprintf( fp, "%02X", skey->key[i] );
  fprintf( fp, "\n");
  skey->set_mask( skey );

  fprintf( fp, "resource:\n value:\t%u (%s)\n", (unsigned int)skey->resource.value.counter,
                              skey->resource.value.type == block_counter_resource ? bc : rc );
  fprintf( fp, " not before: %s", ctime( &skey->resource.time.not_before ));
  fprintf( fp, " not after:  %s", ctime( &skey->resource.time.not_after ));
  fprintf( fp, "flags: [set_key = ");
   if( skey->flags&ak_key_flag_set_key ) fprintf( fp, "SET"); else fprintf( fp, "NOT SET");
  fprintf( fp, ", set_mask = ");
   if( skey->flags&ak_key_flag_set_mask ) fprintf( fp, "SET"); else fprintf( fp, "NOT SET");
  fprintf( fp, ", set_icode = ");
   if( skey->flags&ak_key_flag_set_icode ) fprintf( fp, "SET"); else fprintf( fp, "NOT SET");
  fprintf( fp, ", data_not_free = ");
   if( skey->flags&ak_key_flag_data_not_free ) fprintf( fp, "SET"); else fprintf( fp, "NOT SET");
  fprintf( fp, "]\n\n");

 return  ak_error_ok;
}

#endif
/* ----------------------------------------------------------------------------------------------- */
/*! \example test-skey01.c                                                                         */
/*! \example test-skey02.c                                                                         */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.c  */
/* ----------------------------------------------------------------------------------------------- */
