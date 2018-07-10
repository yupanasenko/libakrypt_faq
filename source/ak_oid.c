/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_oid.h                                                                                  */
/*  - содержит реализации функций для работы с идентификаторами криптографических                  */
/*    алгоритмов и параметров                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_random.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения OID библиотеки */
 struct oid libakrypt_oids[] = {
  /* 1. идентификаторы алгоритмов выработки псевдо-случайных последовательностей,
        значения OID находятся в дереве библиотеки: 1.2.643.2.52.1.1 - генераторы ПСЧ  */
   { random_generator, algorithm, "lcg", "1.2.643.2.52.1.1.1", NULL, NULL,
                                    { (ak_function_void *) ak_random_context_create_lcg,
                                      (ak_function_void *) ak_random_context_destroy, NULL, NULL }},

  #if defined(__unix__) || defined(__APPLE__)
   { random_generator, algorithm, "dev-random", "1.2.643.2.52.1.1.2", NULL, NULL,
                                    { (ak_function_void *) ak_random_context_create_random,
                                      (ak_function_void *) ak_random_context_destroy, NULL, NULL }},

   { random_generator, algorithm, "dev-urandom", "1.2.643.2.52.1.1.3", NULL, NULL,
                                    { (ak_function_void *) ak_random_context_create_urandom,
                                      (ak_function_void *) ak_random_context_destroy, NULL, NULL }},
  #endif
  #ifdef _WIN32
   { random_generator, algorithm, "winrtl", "1.2.643.2.52.1.1.4", NULL, NULL,
                                    { (ak_function_void *) ak_random_context_create_winrtl,
                                      (ak_function_void *) ak_random_context_destroy, NULL, NULL }},
 #endif

   { random_generator, algorithm, "xorshift64", "1.2.643.2.52.1.1.5", NULL, NULL,
                                    { (ak_function_void *) ak_random_context_create_xorshift64,
                                      (ak_function_void *) ak_random_context_destroy, NULL, NULL }},

  /* завершающая константа, должна всегда принимать неопределенные и нулевые значения */
   { undefined_engine, undefined_mode, NULL, NULL, NULL, NULL, { NULL, NULL, NULL, NULL }}
 };

/* ----------------------------------------------------------------------------------------------- */
/*                     реализация функций доступа к глобальному списку OID                         */
/* ----------------------------------------------------------------------------------------------- */
 const size_t ak_libakrypt_oids_count( void )
{
 return ( sizeof( libakrypt_oids )/( sizeof( struct oid )) - 1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*                          поиск OID - функции внутреннего интерфейса                             */
/* ----------------------------------------------------------------------------------------------- */
/*! @param name строка, содержащая символьное (человекочитаемое) имя криптографического механизма
    или параметра.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 const ak_oid ak_oid_context_find_by_name( const char *name )
{
  size_t len = 0, idx = 0;
  if( name == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }
  do{
     if(( strlen( name ) == ( len = strlen( libakrypt_oids[idx].name ))) &&
            ak_ptr_is_equal( (char *)name, (char *)libakrypt_oids[idx].name, len ))
       return (const ak_oid) &libakrypt_oids[idx];

  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_name, __func__, "searching oid with wrong name" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param name строка, содержащая символьную запись строки символов, разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 const ak_oid ak_oid_context_find_by_id( const char *id )
{
  size_t len = 0, idx = 0;
  if( id == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid identifier" );
    return NULL;
  }

  do{
     if(( strlen( id ) == ( len = strlen( libakrypt_oids[idx].id ))) &&
            ak_ptr_is_equal( (char *)id, (char *)libakrypt_oids[idx].id, len ))
       return (const ak_oid) &libakrypt_oids[idx];

  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_id, __func__, "searching oid with wrong idetifier" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографическиого механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 const ak_oid ak_oid_context_find_by_engine( const ak_oid_engine engine )
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
 const ak_oid ak_oid_context_findnext_by_engine( const ak_oid startoid, const ak_oid_engine engine )
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
/*!  \example example-oid.c                                                                        */
/*!  \example test-internal-oid01.c                                                                */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
