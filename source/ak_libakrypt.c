/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_libakrypt.с                                                                            */
/*  - содержит реализацию функций инициализации и тестирования библиотеки.                         */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
 #include <ak_hmac.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_version( void )
{
#ifdef LIBAKRYPT_VERSION
  return LIBAKRYPT_VERSION;
#else
  return "0.7";
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность определения базовых типов данных
    \return В случе успешного тестирования возвращает \ref ak_true (истина).
    В противном случае возвращается ak_false.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 static ak_bool ak_libakrypt_test_types( void )
{
  union {
    ak_uint8 x[4];
    ak_uint32 z;
  } val;

  if( sizeof( ak_int8 ) != 1 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int8 type" );
    return ak_false;
  }
  if( sizeof( ak_uint8 ) != 1 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint8 type" );
    return ak_false;
  }
  if( sizeof( ak_int32 ) != 4 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int32 type" );
    return ak_false;
  }
  if( sizeof( ak_uint32 ) != 4 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint32 type" );
    return ak_false;
  }
  if( sizeof( ak_int64 ) != 8 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int64 type" );
    return ak_false;
  }
  if( sizeof( ak_uint64 ) != 8 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint64 type" );
    return ak_false;
  }

  if( ak_log_get_level() >= ak_log_maximum )
    ak_error_message_fmt( ak_error_ok, __func__, "size of pointer is %d", sizeof( ak_pointer ));

 /* определяем тип платформы: little-endian или big-endian */
  val.x[0] = 0; val.x[1] = 1; val.x[2] = 2; val.x[3] = 3;

#ifdef LIBAKRYPT_BIG_ENDIAN
  ak_libakrypt_set_option("big_endian_architecture", ak_true );
  if( val.z == 50462976 ) {
    ak_error_message( ak_error_wrong_endian, __func__ ,
      "library runs on little endian platform, don't use LIBAKRYPT_BIG_ENDIAN flag while compile library" );
    return ak_false;
  }
#else
  if( val.z == 66051 ) {
    ak_error_message( ak_error_wrong_endian, __func__ ,
      "library runs on big endian platform, use LIBAKRYPT_BIG_ENDIAN flag while compiling library" );
    return ak_false;
  }
#endif

  if( ak_log_get_level() >= ak_log_maximum ) {
    if( ak_libakrypt_get_option( "big_endian_architecture" ) )
      ak_error_message( ak_error_ok, __func__ , "library runs on big endian platform" );
    else ak_error_message( ak_error_ok, __func__ , "library runs on little endian platform" );
  }

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "library applies __m128i base type" );
#endif

#ifdef LIBAKRYPT_HAVE_BUILTIN_MULQ_GCC
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "library applies assembler code for mulq command" );
#endif

#ifdef LIBAKRYPT_HAVE_PTHREAD
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "library runs with pthreads support" );
#endif

#ifdef LIBAKRYPT_HAVE_GMP_H
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "library runs with gmp support" );
#endif

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации алгоритмов хэширования
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static ak_bool ak_libakrypt_test_hash_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing hash functions started" );

 /* тестируем функцию ГОСТ Р 34.11-94 */
  if( ak_hash_test_gosthash94() != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect gosthash94 testing" );
   return ak_false;
  }

 /* тестируем функцию Стрибог256 */
  if( ak_hash_test_streebog256() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect streebog256 testing" );
    return ak_false;
  }

 /* тестируем функцию Стрибог512 */
  if( ak_hash_test_streebog512() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect streebog512 testing" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing hash functions ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации алгоритмов итерационного сжатия
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static ak_bool ak_libakrypt_test_mac_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing mac algorithms started" );

  /* тестируем итерационное применение функций хеширования */
  if( ak_mac_test_hash_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect streebog512 testing" );
    return ak_false;
  }

  if( ak_hmac_test_streebog() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect testing of hmac functions" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing mac algorithms ended successfully" );

 return ak_true;
}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция должна вызываться перед использованием любых криптографических механизмов библиотеки.

   Пример использования функции.

   \code
    int main( void )
   {
     if( ak_libakrypt_create( NULL ) != ak_true ) {
       // инициализация выполнена не успешна => выход из программы
       return ak_libakrypt_destroy();
     }

     // ... здесь код программы ...

    return ak_libakrypt_destroy();
   }
   \endcode

   \param logger Указатель на функцию аудита. Может быть равен NULL.
   \return Функция возвращает \ref ak_true (истина) в случае успешной инициализации и тестирования
   библиотеки. В противном случае, возвращается \ref ak_false. Код ошибки может быть получен
   с помощью вызова функции ak_error_get_value()                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create( ak_function_log *logger )
{
 int error;

 /* перед стартом все должно быть хорошо */
   ak_error_set_value( error = ak_error_ok );

 /* инициализируем систему аудита (вывод сообщений) */
   if(( error = ak_log_set_function( logger )) != ak_error_ok ) {
     ak_error_message( error, __func__ , "audit mechanism not started" );
     return ak_false;
   }

 /* считываем настройки криптографических алгоритмов */
   if( ak_libakrypt_load_options() != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ ,
                                        "unsuccessful load options from libakrypt.conf file" );
     return ak_false;
   }

 /* проверяем длины фиксированных типов данных */
   if( ak_libakrypt_test_types( ) != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "sizes of predefined types is wrong" );
     return ak_false;
   }

 /* проверяем корректность реализации алгоритмов бесключевго хеширования */
   if( ak_libakrypt_test_hash_functions( ) != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of hash functions" );
     return ak_false;
   }

 /* проверяем корректность реализации алгоритмов итерационного сжатия */
   if( ak_libakrypt_test_mac_functions( ) != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of compress methods" );
     return ak_false;
   }

 ak_error_message( ak_error_ok, __func__ , "all crypto mechanisms tested successfully" );
return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_destroy( void )
{
  int error = ak_error_get_value();
  if( error != ak_error_ok )
    ak_error_message( error, __func__ , "before destroing library holds an error" );


  ak_error_message( ak_error_ok, __func__ , "all crypto mechanisms successfully destroyed" );
 return ak_error_get_value();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
