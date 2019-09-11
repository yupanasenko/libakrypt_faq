/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_skey.h                                                                                 */
/*  - содержит реализации функций, предназначенных для хранения и обработки ключевой информации.   */
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
 #include <ak_skey.h>
 #include <ak_hash.h>
 #include <ak_tools.h>

 #include <stdio.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция выделяет массив памяти, достаточный для размещения секретного ключа и
    его маски. Выделение памяти под контекст не происходит.
    \param skey Контекст секретного ключа
    \param size Размер секретного ключа (в октетах)
    \param policy Метод выделения памяти.
    \return В случае успеха возвращается значение \ref ak_error_ok. В случае возникновения
     ошибки возвращается ее код.                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_alloc_memory( ak_skey skey, size_t size, memory_allocation_policy_t policy )
{
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

  skey->data = NULL; /* внутренние данные ключа не определены */
  memset( &(skey->resource), 0, sizeof( struct resource )); /* ресурс ключа не определен */
  memset( skey->icode, 0, sizeof( skey->icode )); /* контрольная сумма ключа не задана */

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
  skey->flags = skey_flag_undefined;
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
    if( !((skey->flags)&skey_flag_data_not_free )) free( skey->data );
  }
  skey->oid = NULL;
  skey->flags = skey_flag_undefined;

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
  if((( skey->flags)&skey_flag_set_mask ) == 0 ) {
    /* создаем маску*/
     if(( error = ak_random_context_random( &skey->generator,
                             skey->key+skey->key_size, (ssize_t)skey->key_size )) != ak_error_ok )
       return ak_error_message( error, __func__ ,
                                                 "wrong generation a random mask for key buffer" );
    /* накладываем маску на ключ */
     jdx = skey->key_size;
     for( idx = 0; idx < skey->key_size; idx++, jdx++ ) skey->key[idx] ^= skey->key[jdx];
    /* меняем значение флага */
     skey->flags |= skey_flag_set_mask;

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
  if( (( skey->flags)&skey_flag_set_mask ) == 0 ) return ak_error_ok;

 /* снимаем маску с ключа (побайтно) */
  jdx = skey->key_size;
  for( idx = 0; idx < skey->key_size; idx++, jdx++ ) {
     skey->key[idx] ^= skey->key[jdx];
     skey->key[jdx] = 0;
  }

 /* меняем значение флага */
  skey->flags ^= skey_flag_set_mask;
 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_skey_context_fletcher_sum( ak_uint32 *key, ak_uint32 *mask,
                                                        size_t count, ak_uint32 *sA, ak_uint32 *sB )
{
  size_t idx = 0;
  ak_uint32 a = 0, b = 0;

  printf("key:  ");
  for( idx = 0; idx < count; idx++ ) printf( "%08x ", key[idx] );
  printf("\n");
  idx =0;
  printf("mask: ");
  for( idx = 0; idx < count; idx++ ) printf( "%08x ", mask[idx] );
  printf("\n");
  idx =0;


  *sA = *sB = 0;
  while( idx++ < count ) {

    printf("[%02u]: %08x:%08x  ->  ", idx, *sA, *sB );
    *sA ^= *key++;
    if( (*sB ^= *sA)&0x80000000 ) *sB = ( *sB << 1 )^0x04C11DB7;
      else *sB = ( *sB << 1 );
    printf("%08x:%08x\n", *sA, *sB );
  }

  a = b = 0; idx = 0;
  while( idx++ < count ) {

    printf("[%02u]: %08x:%08x  ->  ", idx, a, b );
    a ^= *mask++;
    if( (b ^= a)&0x80000000 ) b = ( b << 1 )^0x04C11DB7;
      else b = ( b << 1 );
    printf("%08x:%08x\n", b, b );
  }

}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Контекст секретного ключа.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_icode_xor( ak_skey skey )
{
  union {
    ak_uint8 u8[8];
    ak_uint32 u32[2];
  } sum = { .u32[0] = 0, .u32[1] = 0 };

 /* "стандартные" проверки указателей и выделения памяти */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key context" );
  if( skey->key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );

  size_t blocks = skey->key_size >> 2, /* работаем с блоком длины 4 байта */
           tail = skey->key_size - ( blocks << 2 );

  ak_skey_context_fletcher_sum( (ak_uint32 *)skey->key, (ak_uint32 *)skey->key+blocks,
                                                               blocks, &sum.u32[0], &sum.u32[1] );
  char str[512];
  ak_ptr_to_hexstr_static( sum.u8, 8, str, 512, ak_false );
  printf("code: %s\n", str );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Контекст секретного ключа.

    @return В случае совпадения контрольной суммы ключа функция возвращает истину (\ref ak_true).
    В противном случае, возвращается ложь (\ref ak_false).                                         */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_skey_context_check_icode_xor( ak_skey skey )
{

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.c  */
/* ----------------------------------------------------------------------------------------------- */
