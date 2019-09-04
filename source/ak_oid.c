/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_oid.с                                                                                  */
/*  - содержит реализации функций для работы с идентификаторами криптографических                  */
/*    алгоритмов и параметров                                                                      */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_parameters.h>

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 #include <ak_hash.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения OID библиотеки */
 static struct oid libakrypt_oids[] = {
  /* 1. идентификаторы алгоритмов выработки псевдо-случайных последовательностей,
        значения OID находятся в дереве библиотеки: 1.2.643.2.52.1.1 - генераторы ПСЧ  */
   { random_generator, algorithm, "lcg", "1.2.643.2.52.1.1.1", NULL, NULL,
                                    { ( ak_function_void *) ak_random_context_create_lcg,
                                      ( ak_function_void *) ak_random_context_destroy,
                                      ( ak_function_void *) ak_random_context_delete, NULL, NULL }},

  #if defined(__unix__) || defined(__APPLE__)
   { random_generator, algorithm, "dev-random", "1.2.643.2.52.1.1.2", NULL, NULL,
                                    { ( ak_function_void *) ak_random_context_create_random,
                                      ( ak_function_void *) ak_random_context_destroy,
                                      ( ak_function_void *) ak_random_context_delete, NULL, NULL }},

   { random_generator, algorithm, "dev-urandom", "1.2.643.2.52.1.1.3", NULL, NULL,
                                    { ( ak_function_void *) ak_random_context_create_urandom,
                                      ( ak_function_void *) ak_random_context_destroy,
                                      ( ak_function_void *) ak_random_context_delete, NULL, NULL }},
  #endif
  #ifdef _WIN32
   { random_generator, algorithm, "winrtl", "1.2.643.2.52.1.1.4", NULL, NULL,
                                    { ( ak_function_void *) ak_random_context_create_winrtl,
                                      ( ak_function_void *) ak_random_context_destroy,
                                      ( ak_function_void *) ak_random_context_delete, NULL, NULL }},
  #endif

   { random_generator, algorithm, "xorshift32", "1.2.643.2.52.1.1.5", NULL, NULL,
                                    { ( ak_function_void *) ak_random_context_create_xorshift32,
                                      ( ak_function_void *) ak_random_context_destroy,
                                      ( ak_function_void *) ak_random_context_delete, NULL, NULL }},

  #ifdef LIBAKRYPT_CRYPTO_FUNCTIONS

   { random_generator, algorithm, "hashrnd", "1.2.643.2.52.1.1.6.1", NULL, NULL,
                             { ( ak_function_void *) ak_random_context_create_hashrnd,
                                      ( ak_function_void *) ak_random_context_destroy,
                                      ( ak_function_void *) ak_random_context_delete, NULL, NULL }},

  /* 2. идентификаторы алгоритмов бесключевого хеширования,
        значения OID взяты из перечней КриптоПро и ТК26 (http://tk26.ru/methods/OID_TK_26/index.php)
        в дереве библиотеки: 1.2.643.2.52.1.2 - функции бесключевого хеширования */
   { hash_function, algorithm, "streebog256", "1.2.643.7.1.1.2.2", NULL, NULL,
                           { ( ak_function_void *) ak_hash_context_create_streebog256,
                                        ( ak_function_void *) ak_hash_context_destroy,
                                        ( ak_function_void *) ak_hash_context_delete, NULL, NULL }},

   { hash_function, algorithm, "streebog512", "1.2.643.7.1.1.2.3", NULL, NULL,
                           { ( ak_function_void *) ak_hash_context_create_streebog512,
                                        ( ak_function_void *) ak_hash_context_destroy,
                                        ( ak_function_void *) ak_hash_context_delete, NULL, NULL }},

  #endif

  /* 12. идентификаторы параметров эллиптических кривых, в частности, из Р 50.1.114-2016
         в дереве библиотеки: 1.2.643.2.52.1.12 - параметры эллиптических кривых в форме Вейерштрасса
         в дереве библиотеки: 1.2.643.2.52.1.12.1 - параметры 256 битных кривых
         в дереве библиотеки: 1.2.643.2.52.1.12.2 - параметры 512 битных кривых */
   { identifier, wcurve_params, "id-tc26-gost-3410-2012-256-paramSetTest", "1.2.643.7.1.2.1.1.0",
                                     NULL, (ak_pointer) &id_tc26_gost_3410_2012_256_paramSetTest,
                                                                  { NULL, NULL, NULL, NULL, NULL }},

   { identifier, wcurve_params, "id-tc26-gost-3410-2012-256-paramSetA", "1.2.643.7.1.2.1.1.1",
                                     NULL, (ak_pointer) &id_tc26_gost_3410_2012_256_paramSetA,
                                                                  { NULL, NULL, NULL, NULL, NULL }},

   { identifier, wcurve_params, "id-tc26-gost-3410-2012-256-paramSetB", "1.2.643.7.1.2.1.1.2",
                                      NULL, (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetA,
                                                                  { NULL, NULL, NULL, NULL, NULL }},
   { identifier, wcurve_params, "id-rfc4357-gost-3410-2001-paramSetA", "1.2.643.2.2.35.1",
                                  NULL, (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetA,
                                                                  { NULL, NULL, NULL, NULL, NULL }},

   { identifier, wcurve_params, "id-tc26-gost-3410-2012-256-paramSetC", "1.2.643.7.1.2.1.1.3",
                                      NULL, (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetB,
                                                                  { NULL, NULL, NULL, NULL, NULL }},
   { identifier, wcurve_params, "id-rfc4357-gost-3410-2001-paramSetB", "1.2.643.2.2.35.2",
                                  NULL, (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetB,
                                                                  { NULL, NULL, NULL, NULL, NULL }},

   { identifier, wcurve_params, "id-tc26-gost-3410-2012-256-paramSetD", "1.2.643.7.1.2.1.1.4",
                                      NULL, (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetC,
                                                                  { NULL, NULL, NULL, NULL, NULL }},
   { identifier, wcurve_params, "id-rfc4357-gost-3410-2001-paramSetC", "1.2.643.2.2.35.3",
                                  NULL, (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetC,
                                                                  { NULL, NULL, NULL, NULL, NULL }},
   { identifier, wcurve_params, "id-rfc4357-2001dh-paramset", "1.2.643.2.2.36.0",
                                  NULL, (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetA,
                                                                  { NULL, NULL, NULL, NULL, NULL }},

   { identifier, wcurve_params, "id-tc26-gost-3410-2012-512-paramSetTest", "1.2.643.7.1.2.1.2.0",
                                     NULL, (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetTest,
                                                                  { NULL, NULL, NULL, NULL, NULL }},

   { identifier, wcurve_params, "id-tc26-gost-3410-2012-512-paramSetA", "1.2.643.7.1.2.1.2.1",
                                     NULL, (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetA,
                                                                  { NULL, NULL, NULL, NULL, NULL }},
   { identifier, wcurve_params, "id-tc26-gost-3410-2012-512-paramSetB", "1.2.643.7.1.2.1.2.2",
                                     NULL, (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetB,
                                                                  { NULL, NULL, NULL, NULL, NULL }},
   { identifier, wcurve_params, "id-tc26-gost-3410-2012-512-paramSetC", "1.2.643.7.1.2.1.2.3",
                                     NULL, (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetC,
                                                                  { NULL, NULL, NULL, NULL, NULL }},

 /* завершающая константа, должна всегда принимать неопределенные и нулевые значения */
  { undefined_engine, undefined_mode, NULL, NULL, NULL, NULL, { NULL, NULL, NULL, NULL, NULL }}

 /* при добавлении нового типа (engine)
    не забыть также добавить его обработку в функцию ak_context_node_get_context_oid() */
};

/* ----------------------------------------------------------------------------------------------- */
 static const char *libakrypt_engine_names[] = {
    "identifier",
    "block cipher",
    "stream cipher",
    "hybrid cipher",
    "hash function",
    "hmac function",
    "omac function",
    "mgm function",
    "mac function",
    "sign function",
    "verify function",
    "random generator",
    "oid engine",
    "undefined engine",
};

/* ----------------------------------------------------------------------------------------------- */
 static const char *libakrypt_mode_names[] = {
    "algorithm",
    "parameter",
    "wcurve params",
    "ecurve params",
    "kbox params",
    "ecb",
    "counter",
    "counter_gost",
    "ofb",
    "cbc",
    "cfb",
    "xts",
    "xtsmac",
    "xcrypt",
    "a8",
    "undefined mode"
};

/* ----------------------------------------------------------------------------------------------- */
/*                     реализация функций доступа к глобальному списку OID                         */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_libakrypt_oids_count( void )
{
 return ( sizeof( libakrypt_oids )/( sizeof( struct oid )) - 1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографического механизма.
    @return Функция возвращает указатель на константную строку.                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_engine_name( const oid_engines_t engine )
{
  if( engine > undefined_engine ) {
    ak_error_message_fmt( ak_error_oid_engine, __func__, "incorrect value of engine: %d", engine );
    return ak_null_string;
  }
 return libakrypt_engine_names[engine];
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mode режим криптографического механизма.
    @return Функция возвращает указатель на константную строку.                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_mode_name( const oid_modes_t mode )
{
  if( mode > undefined_mode ) {
    ak_error_message_fmt( ak_error_oid_mode, __func__, "incorrect value of engine mode: %d", mode );
    return ak_null_string;
  }
 return libakrypt_mode_names[mode];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \note Память, для хранения имени и идентификатора алгоритма должна быть выделена заранее.
    Необходимый объем памяти должен быть не менее, чем значение, возвращаемое функцией
    ak_libakrypt_get_oid_max_length().

    @param index Индекс статической структуры oid
    @param engine Указатель на переменную, куда будет помещено значение engine
    @param mode Указатель на переменную, куда будет помещено значение mode
    @param name Указатель на строку, в которую будет скопировано имя алгоритма
    @param name_size Размер буффера, в который будет скопировано имя алгоритма.
    @param oid Указатель на строку, в которую будет скопирован OID -  последовательность чисел,
    разделенных точками.
    @param oid_size Размер буффера, в который будет скопирован идентификатор алгоритма.
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_get_oid_by_index( const size_t index, oid_engines_t *engine, oid_modes_t *mode,
                              char *name, const size_t name_size, char *oid, const size_t oid_size )
{
  size_t len = 0;
  if( index >= ak_libakrypt_oids_count())
    return ak_error_message( ak_error_wrong_index, __func__, "incorrect index value" );

  *engine = libakrypt_oids[index].engine;
  *mode = libakrypt_oids[index].mode;

 /* проверяем размер выделенной области памяти и копируем значения */
  if( name_size < 1 + (len = strlen( libakrypt_oids[index].name )))
    return ak_error_message( ak_error_overflow, __func__, "isufficient memory for name value" );
  memcpy( name, libakrypt_oids[index].name, len );
  name[len] = 0;

  if( oid_size < 1 + (len = strlen( libakrypt_oids[index].id )))
    return ak_error_message( ak_error_overflow, __func__, "isufficient memory for oid value" );
  memcpy( oid, libakrypt_oids[index].id, len );
  oid[len] = 0;

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
 size_t ak_libakrypt_get_oid_max_length( void )
{
  size_t len = 0;
  ssize_t index = ( ssize_t )ak_libakrypt_oids_count();

  while( --index >= 0 ) {
    if( strlen(libakrypt_oids[index].name) > len ) len = strlen(libakrypt_oids[index].name );
    if( strlen(libakrypt_oids[index].id) > len ) len = strlen(libakrypt_oids[index].id );
  }
 return 1 + len;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          поиск OID - функции внутреннего интерфейса                             */
/* ----------------------------------------------------------------------------------------------- */
/*! @param name строка, содержащая символьное (человекочитаемое) имя криптографического механизма
    или параметра.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL и устанавливается код ошибки.  */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_name( const char *name )
{
  size_t len = 0, idx = 0;

 /* надо ли стартовать */
  if( name == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }
 /* перебор по всем возможным значениям */
  do{
     if(( strlen( name ) == ( len = strlen( libakrypt_oids[idx].name ))) &&
                 ak_ptr_is_equal( name, libakrypt_oids[idx].name, len ))
       return  &libakrypt_oids[idx];

  } while( ++idx < ak_libakrypt_oids_count( ));

  //ak_error_message_fmt( ak_error_oid_id, __func__, "searching oid with wrong name \"%s\"", name );
  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param id строка, содержащая символьную запись идентификатора - последовательность чисел,
    разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_id( const char *id )
{
  size_t len = 0, idx = 0;
  if( id == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid identifier" );
    return NULL;
  }

  do{
     if(( strlen( id ) == ( len = strlen( libakrypt_oids[idx].id ))) &&
                 ak_ptr_is_equal( id, libakrypt_oids[idx].id, len ))
       return  &libakrypt_oids[idx];

  } while( ++idx < ak_libakrypt_oids_count( ));


  // ak_error_message_fmt( ak_error_oid_id, __func__,
  //                                          "searching oid with wrong identifier \"%s\"", id );
  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ni строка, содержащая символьную запись имени или идентифиатора - последовательности
    чисел, разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_ni( const char *ni )
{
  size_t len = 0, idx = 0;
  if( ni == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to oid name or identifier" );
    return NULL;
  }

  do{
    /* проверка имени */
     if(( strlen( ni ) == ( len = strlen( libakrypt_oids[idx].name ))) &&
            ak_ptr_is_equal( ni, libakrypt_oids[idx].name, len ))
       return &libakrypt_oids[idx];
    /* проверка идентификатора */
     if(( strlen( ni ) == ( len = strlen( libakrypt_oids[idx].id ))) &&
            ak_ptr_is_equal( ni, libakrypt_oids[idx].id, len ))
       return &libakrypt_oids[idx];

  } while( ++idx < ak_libakrypt_oids_count( ));

  // ak_error_message_fmt( ak_error_oid_id, __func__,
  //                                      "searching oid with wrong name or identifier\"%s\"", ni );
  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографическиого механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_engine( const oid_engines_t engine )
{
  size_t idx = 0;
  do{
     if( libakrypt_oids[idx].engine == engine ) return (const ak_oid) &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_name, __func__, "searching oid with wrong engine" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param startoid предыдущий найденный oid.
    @param engine тип криптографическиого механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_findnext_by_engine( const ak_oid startoid, const oid_engines_t engine )
{
 ak_oid oid = ( ak_oid )startoid;

 if( oid == NULL) {
   ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid" );
   return NULL;
 }

 /* сдвигаемся по массиву OID вперед */
  while( (++oid)->engine != undefined_engine ) {
    if( oid->engine == engine ) return (const ak_oid) oid;
  }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid Тестируемый на корректность адрес
    @return Функция возвращает истину, если заданный адрес `oid` дествительности содержится
    среди предопределенных oid библиотеки.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_oid_context_check( const ak_oid oid )
{
  size_t i;
  bool_t result = ak_false;

  for( i = 0; i < ak_libakrypt_oids_count(); i++ )
     if( (const ak_oid) &libakrypt_oids[i] == oid ) result = ak_true;

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  \example test-oid01.c                                                                         */
/*!  \example test-oid02.c                                                                         */
/*!  \example test-oid03.c                                                                         */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
