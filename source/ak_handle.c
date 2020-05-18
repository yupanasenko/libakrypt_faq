/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_handle.с                                                                               */
/*  - содержит реализацию функций внешнего интерфейса                                              */
/* ----------------------------------------------------------------------------------------------- */

 #include <ak_bckey.h>
 #include <ak_tools.h>
 #include <ak_asn1_keys.h>
 #include <ak_context_manager.h>

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

/* ----------------------------------------------------------------------------------------------- */
/*                              Функции для работы с дескрипторами                                 */
/* ----------------------------------------------------------------------------------------------- */
/*! \param ni Строка символов, которая определяет криптографическое преобразование.
    Это может быть одно из допустимых имен или идентификатор преобразования.
    \param description Произвольная строка символов, которой пользователь может описать
    криптографичекое преобразование. Как правило, используется для хранения комментариев к
    секретным и/или открытым ключам. Допускается использование значения NULL.
    \return Дескриптор криптографического преобразования. В случае ошибки возвращается
    значение \ref ak_error_wrong_handle. Код ошибки может быть получен с помощью
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_handle_new( const char *ni, const char *description )
{
  ak_pointer ctx = NULL;
  int error = ak_error_ok;
  ak_oid oid = ak_oid_context_find_by_ni( ni );

 /* проверяем входные параметры */
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                              "incorrect value of name/identifier (object identifier not found)" );
    return ak_error_wrong_handle;
  }

 /* определяем тип, создаем и инициализируем контекст криптографического преобразования */
  switch( oid->engine ) {

   /* создаем контекст функции хеширования */
    case hash_function:
      if(( ctx = malloc( sizeof( struct hash ))) == NULL ) {
        ak_error_message( ak_error_out_of_memory, __func__,
                                         "incorrect allocation memory for hash function context" );
        return ak_error_wrong_handle;
      }
      if(( error = ((ak_function_hash_context_create *)oid->func.create)( ctx )) != ak_error_ok ) {
        free( ctx );
        ak_error_message( error, __func__, "incorrect creation of hash function context" );
        return ak_error_wrong_handle;
      }
      break;

   /* создаем контекст функции выработки имитовставки hmac */
    case hmac_function:
      if(( ctx = malloc( sizeof( struct hmac ))) == NULL ) {
        ak_error_message( ak_error_out_of_memory, __func__,
                                         "incorrect allocation memory for hmac function context" );
        return ak_error_wrong_handle;
      }
      if(( error = ((ak_function_hash_context_create *)oid->func.create)( ctx )) != ak_error_ok ) {
        free( ctx );
        ak_error_message( error, __func__, "incorrect creation of hmac function context" );
        return ak_error_wrong_handle;
      }
      break;

   /* создаем контекст секретного ключа электронной подписи */
    case sign_function:
      if(( ctx = malloc( sizeof( struct signkey ))) == NULL ) {
        ak_error_message( ak_error_out_of_memory, __func__,
                                         "incorrect allocation memory for sign function context" );
        return ak_error_wrong_handle;
      }
      if(( error = ((ak_function_signkey_context_create *)oid->func.create)( ctx )) != ak_error_ok ) {
        free( ctx );
        ak_error_message( error, __func__, "incorrect creation of sign function context" );
        return ak_error_wrong_handle;
      }
      break;

    case block_cipher:
    case random_generator:

    default: ak_error_message( ak_error_wrong_oid, __func__,
                                                        "object identifier has incorrect engine" );
      return ak_error_wrong_handle;
  }

 /* помещаем контекст в менеджер контекстов и возвращаем полученный дескриптор */
  return ak_libakrypt_add_context( ctx, oid->engine, description );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param handle Дескриптор секретного ключа асимметричного алгоритма.
    \param description Произвольная строка символов, которой пользователь может описать
    криптографичекое преобразование. Как правило, используется для хранения комментариев к
    секретным и/или открытым ключам. Допускается использование значения NULL.
    \return Дескриптор криптографического преобразования. В случае ошибки возвращается
    значение \ref ak_error_wrong_handle. Код ошибки может быть получен с помощью
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_handle_new_from_signkey( ak_handle handle, const char *description )
{
  ak_handle public;
  ak_oid oid = NULL;
  int error = ak_error_ok;
  ak_pointer secret_ctx = NULL, public_ctx = NULL;

 /* получаем контекст */
  if(( secret_ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );

  switch( oid->engine ) {
    case sign_function:
      if( oid->mode != algorithm ) {
        ak_error_message( ak_error_oid_mode, __func__, "unsupported handle, wrong mode");
        return ak_error_wrong_handle;
      }
     /* теперь создаем открытый ключ */
      if(( public_ctx = malloc( sizeof( struct verifykey ))) == NULL ) {
        ak_error_message( ak_error_out_of_memory, __func__,
                                       "incorrect allocation memory for verify function context" );
        return ak_error_wrong_handle;
      }
      if(( error = ak_verifykey_context_create_from_signkey( public_ctx,
                                                                   secret_ctx )) != ak_error_ok ) {
        free( public_ctx );
        ak_error_message( error, __func__, "incorrect creation of verify function context" );
        return ak_error_wrong_handle;

      }
      break;

    default:
      ak_error_message( ak_error_oid_engine, __func__, "unsupported handle, wrong engine");
      return ak_error_wrong_handle;
  }

 /* помещаем контекст в менеджер контекстов и возвращаем полученный дескриптор */
  if(( public = ak_libakrypt_add_context( public_ctx,
                                        verify_function, description )) == ak_error_wrong_handle )
    public_ctx = ak_verifykey_context_delete( public_ctx );

 return public;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_delete( ak_handle handle )
{
  int error = ak_error_ok;
  ak_context_manager manager = NULL;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL )
    return ak_error_message(
                      ak_error_get_value(), __func__ , "using a non initialized context manager" );

 /* уничтожаем контекст */
  if(( error = ak_context_manager_delete_node( manager, handle )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect context destruction" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_get_oid( ak_handle handle, ak_oid_info info )
{
  size_t idx = 0;
  int error = ak_error_ok;
  ak_context_manager manager = NULL;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ ,
                                                       "using a non initialized context manager" );

  if(( error = ak_context_manager_handle_check( manager, handle, &idx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong handle" );

  if( manager->array[idx]->oid == NULL )
    return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer in internal context node" );

  info->engine = manager->array[idx]->oid->engine;
  info->mode = manager->array[idx]->oid->mode;
  info->id =  manager->array[idx]->oid->id;
  info->names = manager->array[idx]->oid->names;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_handle_check_tag( ak_handle handle )
{
  size_t idx = 0;
  int error = ak_error_ok;
  ak_context_manager manager = NULL;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "using a non initialized context manager" );
    return ak_false;
  }

  if(( error = ak_context_manager_handle_check( manager, handle, &idx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong handle" );
    return ak_false;
  }

 /* возвращаем ответ */
  switch( manager->array[idx]->oid->engine ) {
    case hash_function:
    case hmac_function:
    case block_cipher:
    case cmac_function:
    case mgm_function:
    case sign_function: return ak_true;

    default: return ak_false;
  }
}

/* ----------------------------------------------------------------------------------------------- */
 size_t ak_handle_get_tag_size( ak_handle handle )
{
  size_t idx = 0;
  int error = ak_error_ok;
  ak_context_manager manager = NULL;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "using a non initialized context manager" );
    return 0;
  }

  if(( error = ak_context_manager_handle_check( manager, handle, &idx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong handle" );
    return 0;
  }

 /* возвращаем ответ */
  switch( manager->array[idx]->oid->engine ) {
    case hash_function:
      return (( ak_hash )manager->array[idx]->ctx )->data.sctx.hsize;

    case hmac_function:
      return (( ak_hmac )manager->array[idx]->ctx )->ctx.data.sctx.hsize;

    case block_cipher:
      return (( ak_bckey )manager->array[idx]->ctx )->bsize;

    default:
      ak_error_message( ak_error_wrong_oid, __func__, "this handle has'nt tag" );
      return 0;
  }
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_handle_get_context( ak_handle handle, ak_oid *oid, ak_pointer *description )
{
  size_t idx = 0;
  int error = ak_error_ok;
  ak_context_manager manager = NULL;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "using a non initialized context manager" );
    return NULL;
  }

  if(( error = ak_context_manager_handle_check( manager, handle, &idx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong handle" );
    return NULL;
  }

  *oid = manager->array[idx]->oid; /* получаем тип ключа */
  if( description != NULL ) /* если не нужно, то и не возвращаем пользовательское описание */
    *description =  manager->array[idx]->description;
 return manager->array[idx]->ctx;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_handle_check_secret_key( ak_handle handle )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;


 /* получаем данные */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );
    return ak_false;
  }

 /* возвращаем ответ */
  switch( oid->engine ) {
    case block_cipher:
    case stream_cipher:
    case hybrid_cipher:
    case hmac_function:
    case cmac_function:
    case mgm_function:
    case sign_function: return ak_true;

    default: return ak_false;
  }
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_handle_check_public_key( ak_handle handle )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;

 /* получаем данные */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );
    return ak_false;
  }

 /* возвращаем ответ */
  switch( oid->engine ) {
    case verify_function:
      return ak_true;
    default:
      return ak_false;
  }
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_handle_check_curve( ak_handle handle )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;

 /* получаем данные */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );
    return ak_false;
  }

 /* возвращаем ответ */
  switch( oid->engine ) {
    case sign_function:
      return ak_true;

    default:
      return ak_false;
  }
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_handle_check_name( ak_handle handle )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;

 /* получаем данные */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );
    return ak_false;
  }

 /* возвращаем ответ */
  switch( oid->engine ) {
    case sign_function:
    case verify_function:
      return ak_true;

    default:
      return ak_false;
  }
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_handle_check_validity( ak_handle handle ) { return ak_handle_check_name( handle ); }

/* ----------------------------------------------------------------------------------------------- */
/*! \param handle дескриптор криптографического алгоритма.
    \param ni строка, содержащая имя или идентификатор, определяющий тип помещаемых
    данных (attribute type)
    \param string строка с данными

    \return В случае успеха возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_add_name_string( ak_handle handle, const char *ni, const char *string )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;

 /* получаем данные */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );

  switch( oid->engine ) {
    case sign_function:
      return ak_signkey_context_add_name_string( ctx, ni, string );
    case verify_function:
      return ak_verifykey_context_add_name_string( ctx, ni, string );

    default:
      return ak_error_message( ak_error_wrong_oid, __func__,
                                                        "using handle with unsupported features" );
  }
 return ak_error_wrong_handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param handle дескриптор криптографического алгоритма.
    \param ni строка, содержащая имя или идентификатор, определяющий тип помещаемых
    данных (attribute type)
    \param string строка с данными

    \return В случае успеха возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_set_validity( ak_handle handle, time_t not_before, time_t not_after )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;

 /* получаем данные */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );

  switch( oid->engine ) {
    case sign_function:
      return ak_signkey_context_set_validity( ctx, not_before, not_after );
    case verify_function:
      return ak_verifykey_context_set_validity( ctx, not_before, not_after );

    default:
      return ak_error_message( ak_error_wrong_oid, __func__,
                                                        "using handle with unsupported features" );
  }
 return ak_error_wrong_handle;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_set_curve( ak_handle handle, const char *curve )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;

 /* получаем данные */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );
    return ak_false;
  }

 /* возвращаем ответ */
  switch( oid->engine ) {
    case sign_function:
      return ak_signkey_context_set_curve_str( ctx, curve );

    default:
      return ak_error_message( ak_error_wrong_handle, __func__, "using wrong handle ");
  }
 return ak_error_wrong_handle;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \param handle Дескриптор криптографического алгоритма.
    \param hexstr Строка (null-строка), содержащая шестнадцатеричное представление области памяти,
    содержащей ключевое значение
    \param reverse Флаг, при истинном значении которого данные, после преобразования
    из строки символов, будут побайтно развернуты.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_set_key_from_hexstr( ak_handle handle, const char *hexstr, const bool_t reverse )
{
  ak_oid oid = NULL;
  ak_uint64 key[64];
  struct random rnd;
  ak_pointer ctx = NULL;
  int error = ak_error_ok;

  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );

  if(( error = ak_hexstr_to_ptr( hexstr, key, sizeof( key ), reverse )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect hexademal string with secret key value" );

 /* присваиваем ключ */
  switch( oid->engine ) {
    case hmac_function:
      error = ak_hmac_context_set_key( ctx, key, 64 );
      break;

    case block_cipher:
      error = ak_bckey_context_set_key( ctx, key, 32 );
      break;

    case sign_function:
     /* мы присваиваем ключ длины, совпадающей с длиной хеш кода функции */
      error = ak_signkey_context_set_key( ctx, key, ak_signkey_context_get_tag_size( ctx ) >> 1 );
      break;

    default: error = ak_error_message( ak_error_wrong_oid, __func__,
                                                            "this handle not accept a key value" );
  }

 /* очищаем временную переменную */
  if( ak_random_context_create_lcg( &rnd ) != ak_error_ok ) {
    memset( key, 0, sizeof( key ));
  } else {
           ak_ptr_context_wipe( key, sizeof( key ), &rnd );
           ak_random_context_destroy( &rnd );
         }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_set_key_from_password( ak_handle handle,
                                           const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;
  int error = ak_error_ok;

 /* получаем контекст */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );

 /* присваиваем ключ */
  switch( oid->engine ) {
    case hmac_function:
      error = ak_hmac_context_set_key_from_password( ctx, pass, pass_size, salt, salt_size );
      break;

    case block_cipher:
      error = ak_bckey_context_set_key_from_password( ctx, pass, pass_size, salt, salt_size );
      break;

    default: error = ak_error_message( ak_error_wrong_oid, __func__,
                                              "this handle not accept a key value from password" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_set_key_random( ak_handle handle )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;
  int error = ak_error_ok;
  ak_context_manager manager = NULL;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL )
    return ak_error_message(
                      ak_error_get_value(), __func__ , "using a non initialized context manager" );
 /* получаем контекст */
  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );

 /* присваиваем ключ */
  switch( oid->engine ) {
    case hmac_function:
      error = ak_hmac_context_set_key_random( ctx, &manager->key_generator );
      break;

    case block_cipher:
      error = ak_bckey_context_set_key_random( ctx, &manager->key_generator );
      break;

    case sign_function:
      error = ak_signkey_context_set_key_random( ctx, &manager->key_generator );
      break;

    default: error = ak_error_message( ak_error_wrong_oid, __func__,
                                              "this handle not accept a key value from password" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param handle Дескриптор криптографического алгоритма.
    \param filename Имя файла, для которого вычисляется хеш-код.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделенной памяти должен быть не менее значения, возвращаемого
    функцией ak_handle_get_tag_size().
    \param out_size Размер области памяти (в октетах), в которую будет помещен результат.
    Если данное значение меньше, чем необходимо, то будет возвращена ошибка.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_mac_file( ak_handle handle, const char *filename,
                                                            ak_pointer out, const size_t out_size )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;

  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__, "using handle with wrong mode" );

 /* для тех, кто умеет, возвращаем результат */
   switch( oid->engine )
  {
    case hash_function: return ak_hash_context_file( ctx, filename, out, out_size );
    case hmac_function: return ak_hmac_context_file( ctx, filename, out, out_size );

   /* для остальных возвращаем ошибку */
    default:
        return ak_error_message( ak_error_oid_engine, __func__, "using handle with wrong engine" );
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция позволяет вычислить значение хэш-кода (контрольную сумму) для бесключевых функций
    хэширования или значение имитовставки - для ключевых функций хэширования.

    \param handle Дескриптор криптографического алгоритма.
    \param in Указатель на входные данные для которых вычисляется контрольная сумма.
    \param size Размер входных данных в байтах.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделенной памяти должен быть не менее значения, возвращаемого
    функцией ak_handle_get_tag_size().
    \param out_size Размер области памяти (в октетах), в которую будет помещен результат.
    Если данное значение меньше, чем необходимо, то будет возвращена ошибка.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_mac_ptr( ak_handle handle, ak_pointer in, const size_t size,
                                                             ak_pointer out, const size_t out_size )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;

  if(( ctx = ak_handle_get_context( handle, &oid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__, "using handle with wrong mode" );

 /* для тех, кто умеет, возвращаем результат */
   switch( oid->engine )
  {
    case hash_function: return ak_hash_context_ptr( ctx, in, size, out, out_size );
    case hmac_function: return ak_hmac_context_ptr( ctx, in, size, out, out_size );

   /* для остальных возвращаем ошибку */
    default:
        return ak_error_message( ak_error_oid_engine, __func__, "using handle with wrong engine" );
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция зашифровывает секретный ключ на пароле пользователя и сохраняет его в файл.

    \param handle Дескриптор криптографического алгоритма. Алгоритм должен содержать
    секретный ключ.
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \param format формат, в котором зашифрованные данные сохраняются в файл.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_export_to_file_with_password( ak_handle handle, const char *password,
                const size_t pass_size, char *filename, const size_t size, export_format_t format )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;
  ak_pointer keyname = NULL;

  if(( ctx = ak_handle_get_context( handle, &oid, &keyname )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect handle value" );

 return ak_key_context_export_to_file_with_password( ctx, oid->engine,
                                            password, pass_size, keyname, filename, size, format );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param public Дескриптор открытого ключа асимметричного криптографического механизма.
    \param secret Дескриптор секретного ключа асимметричного криптографического механизма.
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \param format формат, в котором зашифрованные данные сохраняются в файл.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_export_to_request( ak_handle public, ak_handle secret,
                                        char *filename, const size_t size, export_format_t format )
{
  ak_oid pid = NULL, sid = NULL;
  ak_pointer pctx = NULL, sctx = NULL;

 /* проверяем дескрипторы */
  if(( pctx = ak_handle_get_context( public, &pid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect public key handle" );
  switch( pid->engine ) {
    case verify_function:
      if( pid->mode != algorithm ) return ak_error_message( ak_error_oid_mode, __func__,
                                                     "unsupported public key handle, wrong mode");
      break;
    default:
      return ak_error_message( ak_error_oid_engine, __func__, "unsupported handle, wrong engine");
  }
  if(( sctx = ak_handle_get_context( secret, &sid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect secret key handle" );
  switch( sid->engine ) {
    case sign_function:
      if( sid->mode != algorithm ) return ak_error_message( ak_error_oid_mode, __func__,
                                                     "unsupported secret key handle, wrong mode");
      break;
    default:
      return ak_error_message( ak_error_oid_engine, __func__, "unsupported handle, wrong engine");
  }

 return ak_verifykey_context_export_to_request( pctx, sctx, filename, size, format );
}


/* ----------------------------------------------------------------------------------------------- */
/*! \param public Дескриптор открытого ключа асимметричного криптографического механизма.
    \param secret Дескриптор секретного ключа асимметричного криптографического механизма.
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \param format формат, в котором зашифрованные данные сохраняются в файл.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 dll_export int ak_handle_export_to_certificate( ak_handle public, ak_handle secret,
              ak_certificate_opts opts, char *filename, const size_t size, export_format_t format )
{
  ak_oid pid = NULL, sid = NULL;
  ak_pointer pctx = NULL, sctx = NULL;

 /* проверяем дескрипторы, аналогично тому, как это делалось в экспорте запроса на сертификат */
  if(( pctx = ak_handle_get_context( public, &pid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect public key handle" );
  switch( pid->engine ) {
    case verify_function:
      if( pid->mode != algorithm ) return ak_error_message( ak_error_oid_mode, __func__,
                                                     "unsupported public key handle, wrong mode");
      break;
    default:
      return ak_error_message( ak_error_oid_engine, __func__, "unsupported handle, wrong engine");
  }
  if(( sctx = ak_handle_get_context( secret, &sid, NULL )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect secret key handle" );
  switch( sid->engine ) {
    case sign_function:
      if( sid->mode != algorithm ) return ak_error_message( ak_error_oid_mode, __func__,
                                                     "unsupported secret key handle, wrong mode");
      break;
    default:
      return ak_error_message( ak_error_oid_engine, __func__, "unsupported handle, wrong engine");
  }

 return ak_verifykey_context_export_to_certificate( pctx, sctx, opts, filename, size, format );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_handle.c  */
/* ----------------------------------------------------------------------------------------------- */
