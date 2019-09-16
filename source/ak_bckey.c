/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_bckey.h                                                                                */
/*  - содержит реализацию общих функций для алгоритмов блочного шифрования.                        */
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
 #include <ak_tools.h>
 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает параметры алгоритма блочного шифрования, передаваемые в качестве
    аргументов. После инициализации остаются неопределенными следующие поля и методы,
    зависящие от конкретной реализации алгоритма блочного шифрования:

    - bkey.encrypt -- алгоритм зашифрования одного блока
    - bkey.decrypt -- алгоритм расшифрования одного блока
    - bkey.shedule_keys -- алгоритм развертки ключа и генерации раундовых ключей
    - bkey.delete_keys -- функция удаления раундовых ключей

    Следующие поля принимают значения по-умолчанию
    - bkey.key.data -- указатель на служебную область памяти
    - bkey.key.resource.value.counter -- максимально возможное число обрабатываемых блоков информации
    - bkey.key.oid -- идентификатор алгоритма шифрования
    - bkey.key.set_mask -- функция установки или смены маски ключа
    - bkey.key.unmask -- функция снятия маски с ключа
    - bkey.key.set_icode -- функция вычисления кода целостности
    - bkey.key.check_icode -- функция проверки кода целостности

    Перечисленные методы могут переопределяться в производящих функциях,
    создающих объекты конкретных алгоритмов блочного шифрования.

    @param bkey контекст ключа алгоритма блочного шифрованния
    @param keysize длина ключа в байтах
    @param blocksize длина блока обрабатываемых данных в байтах
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_create( ak_bckey bkey, size_t keysize, size_t blocksize )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using a null pointer to block cipher context" );
  if( !keysize ) return ak_error_message( ak_error_zero_length, __func__,
                                                        "using block cipher key with zero length" );
  if( !blocksize ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using cipher with zero block length" );
 /* инициализируем ключевые данные */
  if(( error = ak_skey_context_create( &bkey->key, keysize )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of secret key" );

  memset( bkey->ivector, 0, sizeof( bkey->ivector ));
  bkey->bsize =         blocksize;
  bkey->ivector_size =  0;
  bkey->encrypt =       NULL;
  bkey->decrypt =       NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =   NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey контекст ключа алгоритма блочного шифрованния
    @return В случае успеха функция возввращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_destroy( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using a null pointer to block cipher context" );
  if( bkey->delete_keys != NULL ) {
    if(( error = bkey->delete_keys( &bkey->key )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong deleting of round keys" );
    }
  }
 /* изменяем значение вектора синхропосылок перед уничтожением */
  if(( error =  ak_ptr_context_wipe( bkey->ivector, sizeof( bkey->ivector ),
                                                          &bkey->key.generator )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect wiping of internal buffer" );
  bkey->ivector_size = 0;

 /* уничтожаем секретный ключ */
  if(( error = ak_skey_context_destroy( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroying a secret key" );

  bkey->bsize =            0;
  bkey->encrypt =       NULL;
  bkey->decrypt =       NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =   NULL;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey контекст ключа алгоритма блочного шифрованния
    @return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_bckey_context_delete( ak_pointer bkey )
{
  if( bkey != NULL ) {
    ak_bckey_context_destroy( bkey );
    free( bkey );
  } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                    "using null pointer to block cipher context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey контекст ключа алгоритма блочного шифрованния
    @param oid Идентификатор алгоритма HMAC - ключевой функции хеширования.
    @return В случае успешного завершения функция возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_create_oid( ak_bckey bkey, ak_oid oid )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using a null pointer to block cipher context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using a null pointer to oid context" );
 /* проверяем, что OID от правильного алгоритма выработки */
  if( oid->engine != block_cipher )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );
 /* проверяем, что производящая функция определена */
  if( oid->func.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                             "using block cipher oid with undefined constructor" );
 /* инициализируем контекст */
  if(( error = (( ak_function_bckey_create *)oid->func.create )( bkey )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                                    "invalid creation of %s block cipher context", oid->names[0] );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция присваивает контексту ключа алгоритма блочного шифрования заданное значение,
    содержащееся в области памяти, на которую указывает аргумент функции keyptr.
    При инициализации значение ключа \b копируется в контекст ключа.

    Перед присвоением ключа контекст должен быть инициализирован.
    После присвоения ключа производится его маскирование и выработка контрольной суммы.

    Предпалагается, что основное использование функции ak_bckey_context_set_key()
    заключается в тестировании алгоритма блочного шифрования на заданных (тестовых)
    значениях ключей. Другое использование функции - присвоение значений, выработанных в ходе
    выполнения алгоритмов выработки ключевой информации.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param keyptr Указатель на область памяти, содержащую значение ключа.
    @param size Размер области памяти, содержащей значение ключа.

    @return Функция возвращает код ошибки. В случае успеха возвращается \ref ak_error_ok (ноль).   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_set_key( ak_bckey bkey, const ak_pointer keyptr, const size_t size )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( keyptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                "using null pointer to key data" );
  if( size != bkey->key.key_size ) return ak_error_message( ak_error_wrong_length, __func__,
                                       "using a constant value for secret key with wrong length" );
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_context_set_key( &bkey->key, keyptr, size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of fixed key data" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) {
    if(( error = bkey->schedule_keys( &bkey->key )) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );
  }
 /* устанавливаем ресурс использования секретного ключа */
  switch( bkey->bsize ) {
    case  8: if(( error = ak_skey_context_set_resource( &bkey->key,
                      block_counter_resource, "magma_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__, "incorrect assigning \"magma_cipher_resource\" option" );
      break;

    case 16: if(( error = ak_skey_context_set_resource( &bkey->key,
                     block_counter_resource, "kuznechik_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__,
                                      "incorrect assigning \"kuznechik_cipher_resource\" option" );
      break;
    default:  ak_error_message( error = ak_error_wrong_block_cipher_length, __func__,
                                                        "incorrect value of block cipher length" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает контексту ключа алгоритма блочного шифрования случайное (псевдослучайное)
    значение, вырабатываемое заданным генератором случайных (псевдослучайных) чисел.

    Перед присвоением ключа контекст должен быть инициализирован.

    После присвоения значения ключа производится его маскирование и выработка контрольной суммы.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param generator Контекст генератора случайных (псевдослучайных) чисел.

    @return Функция возвращает код ошибки. В случае успеха возвращается \ref ak_error_ok.          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_set_key_random( ak_bckey bkey, ak_random generator )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to secret key context" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                          "using null pointer to random generator" );
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_context_set_key_random( &bkey->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of random key data" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) error = bkey->schedule_keys( &bkey->key );
  if( error != ak_error_ok )
    ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );

 /* устанавливаем ресурс использования секретного ключа */
  switch( bkey->bsize ) {
    case  8: if(( error = ak_skey_context_set_resource( &bkey->key,
                      block_counter_resource, "magma_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__, "incorrect assigning \"magma_cipher_resource\" option" );
      break;

    case 16: if(( error = ak_skey_context_set_resource( &bkey->key,
                     block_counter_resource, "kuznechik_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__,
                                      "incorrect assigning \"kuznechik_cipher_resource\" option" );
      break;
    default:  ak_error_message( error = ak_error_wrong_block_cipher_length, __func__,
                                                        "incorrect value of block cipher length" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает контексту ключа блочного шифрования значение, выработанное из заданного
    пароля при помощи алгоритма PBKDF2, описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    Количество итераций алгоритма PBKDF2 определяется опцией библиотеки `pbkdf2_iteration_count`,
    значение которой может быть опредедено с помощью вызова функции ak_libakrypt_get_option().

    Перед присвоением ключа контекст должен быть инициализирован.

    После присвоения значения ключа производится его маскирование и выработка контрольной суммы.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param pass Пароль, представленный в виде строки символов.
    @param pass_size Длина пароля в байтах
    @param salt Случайный вектор, представленный в виде строки символов.
    @param salt_size Длина случайного вектора в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_set_key_from_password( ak_bckey bkey, const ak_pointer pass,
                             const size_t pass_size, const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to secret key context" );
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_context_set_key_from_password( &bkey->key,
                                                pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning for given password" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) error = bkey->schedule_keys( &bkey->key );
  if( error != ak_error_ok )
    ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );

 /* устанавливаем ресурс использования секретного ключа */
  switch( bkey->bsize ) {
    case  8: if(( error = ak_skey_context_set_resource( &bkey->key,
                      block_counter_resource, "magma_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__, "incorrect assigning \"magma_cipher_resource\" option" );
      break;

    case 16: if(( error = ak_skey_context_set_resource( &bkey->key,
                     block_counter_resource, "kuznechik_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__,
                                      "incorrect assigning \"kuznechik_cipher_resource\" option" );
      break;
    default:  ak_error_message( error = ak_error_wrong_block_cipher_length, __func__,
                                                        "incorrect value of block cipher length" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_bckey.c  */
/* ----------------------------------------------------------------------------------------------- */
