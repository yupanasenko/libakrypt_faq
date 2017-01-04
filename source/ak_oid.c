/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2016 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*   Redistribution and use in source and binary forms, with or without modification, are          */
/*   permitted provided that the following conditions are met:                                     */
/*                                                                                                 */
/*   1. Redistributions of source code must retain the above copyright notice, this list of        */
/*      conditions and the following disclaimer.                                                   */
/*   2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/*      conditions and the following disclaimer in the documentation and/or other materials        */
/*      provided with the distribution.                                                            */
/*   3. Neither the name of the copyright holder nor the names of its contributors may be used     */
/*      to endorse or promote products derived from this software without specific prior written   */
/*      permission.                                                                                */
/*                                                                                                 */
/*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/*   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/*   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL        */
/*   THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, */
/*   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/*   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/*   AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/*   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/*   OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/*                                                                                                 */
/*   ak_oid.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
 #define ak_oids_array_count (64)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Статическая структура указателей на массив OID библиотеки */
 static struct {
   ak_oid array[ak_oids_array_count];
   size_t count;
 } global_oids_array;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Мьютекс для блокировки массива OID'ов при добавлении новых значений */
 static pthread_mutex_t ak_oids_add_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief ункция добавляет новый OID в массив
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

 /* идентификаторы отечественных криптографических алгоритмов
    взяты согласно перечню OID c http://tk26.ru/methods/OID_TK_26/index.php  и
    из используемых перечней КриптоПро                                                             */

 /* в начале, добавляем идентификаторы алгоритмов бесключевого хеширования */
  ak_oids_add_oid( ak_oid_new( hash_function, algorithm, "streebog256", "1.2.643.7.1.1.2.2", NULL ));
  ak_oids_add_oid( ak_oid_new( hash_function, algorithm, "streebog512", "1.2.643.7.1.1.2.3", NULL ));
  ak_oids_add_oid( ak_oid_new( hash_function, algorithm, "gosthash94", "1.2.643.2.2.9", NULL ));

  /* добавляем таблицы замен для функции хеширования ГОСТ Р 34.11-94 */
  ak_oids_add_oid( ak_oid_new( hash_function, kbox_params,
                          "id-gosthash94-TestParamSet", "1.2.643.2.2.30.0", (ak_pointer) hash_box ));
  ak_oids_add_oid( ak_oid_new( hash_function, kbox_params,
             "id-gosthash94-CryptoPro-A-ParamSet", "1.2.643.2.2.30.1", (ak_pointer) hash_box_CSPA ));
  ak_oids_add_oid( ak_oid_new( hash_function, kbox_params,
                "id-gosthash94-VerbaO-ParamSet", "1.2.643.2.2.30.2", (ak_pointer) hash_box_VerbaO ));

  /* добавляем алгоритмы блочного шифрования */
  ak_oids_add_oid( ak_oid_new( block_cipher, algorithm, "magma", "1.2.643.2.2.21", NULL ));
  ak_oids_add_oid( ak_oid_new( block_cipher, algorithm, "kuznetchik", "1.2.643.7.1.1.5.1", NULL ));

  /* добавляем таблицы замен для алгоритма блочного шифрования ГОСТ 28147-89 (Магма) */
  ak_oids_add_oid( ak_oid_new( block_cipher, kbox_params,
                             "id-magma-TestParamSet", "1.2.643.2.2.31.0", (ak_pointer) cipher_box ));
  ak_oids_add_oid( ak_oid_new( block_cipher, kbox_params,
                "id-magma-CryptoPro-A-ParamSet", "1.2.643.2.2.31.1", (ak_pointer) cipher_box_CSPA ));
  ak_oids_add_oid( ak_oid_new( block_cipher, kbox_params,
            "id-magma-gost3412-2015-ParamSet", "1.2.643.2.52.31.1", (ak_pointer) cipher_box_magma ));

  /* добавляем параметры эллиптических кривых */
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-gost3410-2012-test256",
                               "1.2.643.7.1.2.1.1.0", (ak_pointer) &wcurve_gost_3410_2012_test256 ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-gost3410-2012-test512",
                               "1.2.643.7.1.2.1.2.0", (ak_pointer) &wcurve_gost_3410_2012_test512 ));

  /* рекомендации Росстандарта Р 50.1.114-2016
    ­ id-tc26-gost-3410-12-512-paramSetA,    1.2.643.7.1.2.1.2.1
     id-tc26-gost-3410-12-512-paramSetB,    1.2.643.7.1.2.1.2.2
    ­ id-tc26-gost-3410-2012-256-paramSetA,  1.2.643.7.1.2.1.1.1
     id-tc26-gost-3410-2012-512-paramSetC,  1.2.643.7.1.2.1.2.3

     а также КриптоПро (RFC 4357) */

  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-tc26-gost3410-2012-256-paramSetA",
                    "1.2.643.7.1.2.1.1.1", (ak_pointer) &wcurve_tc26_gost_3410_2012_256_paramSetA ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-cryptoPro-gost3410-2001-paramSetA",
                                       "1.2.643.2.2.35.1", (ak_pointer) &wcurve_rfc4357_paramSetA ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-cryptoPro-gost3410-2001-paramSetB",
                                       "1.2.643.2.2.35.2", (ak_pointer) &wcurve_rfc4357_paramSetB ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-cryptoPro-gost3410-2001-paramSetC",
                                       "1.2.643.2.2.35.3", (ak_pointer) &wcurve_rfc4357_paramSetC ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-cryptoPro-2001DH-paramSet",
                                       "1.2.643.2.2.36.0", (ak_pointer) &wcurve_rfc4357_paramSetA ));

  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-axel-gost3410-2012-256-paramSetA",
                "1.2.643.2.52.1.25.1.2.1", (ak_pointer) &wcurve_axel_gost_3410_2012_256_paramSetA ));

  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-tc26-gost3410-2012-512-paramSetA",
                    "1.2.643.7.1.2.1.2.1", (ak_pointer) &wcurve_tc26_gost_3410_2012_512_paramSetA ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-tc26-gost3410-2012-512-paramSetB",
                    "1.2.643.7.1.2.1.2.2", (ak_pointer) &wcurve_tc26_gost_3410_2012_512_paramSetB ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-tc26-gost3410-2012-512-paramSetC",
                    "1.2.643.7.1.2.1.2.3", (ak_pointer) &wcurve_tc26_gost_3410_2012_512_paramSetC ));

  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-axel-gost3410-2012-512-paramSetA",
                "1.2.643.2.52.1.27.1.2.1", (ak_pointer) &wcurve_axel_gost_3410_2012_512_paramSetA ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-axel-gost3410-2012-512-paramSetB",
                "1.2.643.2.52.1.27.1.2.2", (ak_pointer) &wcurve_axel_gost_3410_2012_512_paramSetB ));
  ak_oids_add_oid( ak_oid_new( identifier, wcurve_params, "id-axel-gost3410-2012-512-paramSetC",
                "1.2.643.2.52.1.27.1.2.3", (ak_pointer) &wcurve_axel_gost_3410_2012_512_paramSetC ));

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
/*! \brief Получение общего количества OID в библиотеке
    @return функция возвращает количество OID в случае успеха. В случае возникновения ошибки,
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
/*! @param name строка символов - читаемое пользователем имя таблицы замен
    @param id строка, содержащая числа, разделенные точками - идентификатор таблицы замен
    @param table -- двумерный массив, содержащий 8 строк по 16 чисел. Каждая строка задает
    одну перестановку на множестве \f$ \{0, \ldots, 15 \}\f$.

    @return В случае успеха, функция возвращает ноль (ak_error_ok).  В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oids_add_magma_tables( const char *name, const char *id, const ak_uint8 table[8][16] )
{
  ak_uint8 v[16];
  int i = 0, j = 0, result = 0;

  if( name == NULL ) {
    ak_error_message( ak_error_oid_name, __func__ , "using a null pointer to OID name" );
    return ak_error_oid_name;
  }
  if( id == NULL ) {
    ak_error_message( ak_error_oid_id, __func__ , "using a null pointer to OID identifier" );
    return ak_error_oid_id;
  }
  if( table == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to magma tables" );
    return ak_error_null_pointer;
  }
  if( global_oids_array.count >= ak_oids_array_count ) {
    ak_error_message( ak_error_oid_index, __func__ , "new oid exceeds permissible bounds" );
    return ak_error_oid_index;
  }

 /* далее мы проверяем, что входные данные действительно являются перестановками для ГОСТ 28147-89 */
  for( i = 0; i < 8; i++ ) {
     memset( v, 0, 16 ); /* обнуляем счетчик */
     for( j = 0; j < 16; j++ ) if( table[i][j] < 16 ) v[ table[i][j] ]++;
     for( j = 0; j < 16; j++ ) if( v[j] != 1) result++;
  }
  if( result ) {
    ak_error_message_fmt( ak_error_undefined_value, __func__ ,
                      "using a data which not represent a magma tables with %d errors", result );
    return ak_error_undefined_value;
  }
  return ak_oids_add_oid( ak_oid_new( block_cipher, kbox_params, name, id, (ak_pointer) table ));
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
/*!  \example example-oid.c
     \example example-oid-magma.c
     \example example-oid-wcurve.c                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
