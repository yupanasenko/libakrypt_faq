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
 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
 static const ak_uint8 acpkm_D[32] = {

     0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
     0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80 };
/* ----------------------------------------------------------------------------------------------- */

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
 /* инициализируем данные,
    для ключей блочного шифрования длина контрольной суммы всегда равна 8 байт */
  if(( error = ak_skey_context_create( &bkey->key, keysize, 8 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of secret key" );

 /* структура, хранящая синхропосылку инициализируется нулевым значением */
  if(( error = ak_buffer_create( &bkey->ivector )) != ak_error_ok ) {
    if( ak_skey_context_destroy( &bkey->key ) != ak_error_ok )
      ak_error_message( ak_error_get_value(), __func__, "wrong destroying a secret key" );
    return ak_error_message( error, __func__, "wrong memory allocation for temporary vector");
  }

  bkey->bsize =    blocksize;
  bkey->encrypt =       NULL;
  bkey->decrypt =       NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =   NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey контекст ключа алгоритма блочного шифрованния
    @return В случае успеха функция возввращает ak_error_ok (ноль).
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
  if( ak_buffer_is_assigned( &bkey->ivector ))
    ak_buffer_wipe( &bkey->ivector, &bkey->key.generator );
  if(( error = ak_buffer_destroy( &bkey->ivector )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroying a temporary vector" );

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
                                                         "using null pointer to block cipher key" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает контексту ключа алгоритма блочного шифрования заданное значение,
    содержащееся в области памяти, на которую указывает аргумент функции keyptr.
    При инициализации значение ключа \b копируется в контекст ключа, если флаг cflag истиннен.
    Если флаг ложен, то копирования (размножения ключевой информации) не происходит.
    Поведение функции при копировании аналогично поведению функции ak_buffer_set_ptr().

    Перед присвоением ключа контекст должен быть инициализирован.

    После присвоения значения ключа производится его маскирование и выработка контрольной суммы.

    Предпалагается, что основное использование функции ak_bckey_context_set_key()
    заключается в тестировании алгоритма блочного шифрования на заданных (тестовых)
    значениях ключей. Другое использование функции - присвоение значений, выработанных в ходе
    выполнения алгоритмов выработки ключевой информации.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param keyptr Указатель на область памяти, содержащую значение ключа.
    @param size Размер области памяти, содержащей значение ключа.
    @param cflag Флаг владения данными. Если он истинен, то данные копируются в область памяти,
    которой владеет ключевой контекст.

    @return Функция возвращает код ошибки. В случае успеха возвращается ak_error_ok (ноль).        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_set_key( ak_bckey bkey,
                                   const ak_pointer keyptr, const size_t size, const bool_t cflag )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to secret key context" );
  if( keyptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                  "using null pointer to key data" );
  if( size != bkey->key.key.size ) return ak_error_message( ak_error_wrong_length, __func__,
                                         "using a constant value for secret key with wrong length" );
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_context_set_key( &bkey->key, keyptr, size, cflag )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of fixed key data" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) bkey->schedule_keys( &bkey->key );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает контексту ключа алгоритма блочного шифрования случайное (псевдослучайное)
    значение, вырабатываемое заданным генератором случайных (псевдослучайных) чисел.

    Перед присвоением ключа контекст должен быть инициализирован.

    После присвоения значения ключа производится его маскирование и выработка контрольной суммы.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param generator Контекст генератора случайных (псевдослучайных) чисел.

    @return Функция возвращает код ошибки. В случае успеха возвращается ak_error_ok.               */
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
  if( bkey->schedule_keys != NULL ) bkey->schedule_keys( &bkey->key );

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

    @return В случае успеха возвращается значение ak_error_ok. В противном случае
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
  if( bkey->schedule_keys != NULL ) bkey->schedule_keys( &bkey->key );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             теперь реализация режимов шифрования                                */
/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Контекст ключа алгоритма блочного шифрования.
    @param in Указатель на область памяти, где хранятся входные (зашифровываемые) данные
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах). Для режима простой замены
    длина зашифровываемых данных должна быть кратна длине блока.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_encrypt_ecb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size )
{
  ak_int64 blocks = 0;
  int error = ak_error_ok;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* выполняем проверку размера входных данных */
  if( size%bkey->bsize != 0 )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  blocks = (ak_uint64 ) size/bkey->bsize;
  if( bkey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                                   __func__ , "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= blocks;

 /* теперь приступаем к зашифрованию данных */
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита */
      do {
        bkey->encrypt( &bkey->key, inptr++, outptr++ );
      } while( --blocks > 0 );
    break;

    case 16: /* шифр с длиной блока 128 бит */
      do {
        bkey->encrypt( &bkey->key, inptr, outptr );
        inptr+=2; outptr+=2;
      } while( --blocks > 0 );
    break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
  }
 /* перемаскируем ключ */
  if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Контекст ключа алгоритма блочного шифрования.
    @param in Указатель на область памяти, где хранятся входные (расшифровываемые) данные.
    @param out Указатель на область памяти, куда помещаются расшифрованные данные
    (этот указатель может совпадать с in).
    @param size Размер расшировываемых данных (в байтах). Для режима простой замены
    длина расшифровываемых данных должна быть кратна длине блока.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_decrypt_ecb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size )
{
  ak_int64 blocks = 0;
  int error = ak_error_ok;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* выполняем проверку размера входных данных */
  if( size%bkey->bsize != 0 )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  blocks = (ak_uint64 ) size/bkey->bsize;
  if( bkey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                                   __func__ , "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= blocks;

 /* теперь приступаем к расшифрованию данных */
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита */
      do {
        bkey->decrypt( &bkey->key, inptr++, outptr++ );
      } while( --blocks > 0 );
    break;

    case 16: /* шифр с длиной блока 128 бит */
      do {
        bkey->decrypt( &bkey->key, inptr, outptr );
        inptr+=2; outptr+=2;
      } while( --blocks > 0 );
    break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
  }
 /* перемаскируем ключ */
  if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! В режиме гаммирования операцией шифрования является сложение открытого текста по модулю два
    с последовательностью, вырабатываемой блочным шифром, поэтому для зашифрования и расшифрования
    информациии используется одна и та же функция.

    Значение синхропосылки `iv` копируется в контекст секретного ключа (область памяти, на которую
    указывает `iv` не изменяется) и, в ходе реализации режима гаммирования, преобразуется.
    Преобразованное значение сохраняется в контексте секретного ключа в буффере `skey.ivector`.
    Данное значение может быть использовано при повторном вызове функции ak_bckey_context_ctr().
    Следующий пример иллюстрирует сказанное.

\code

 // шифрование буффера с данными одним фрагментом
  ak_bckey_context_ctr( key, in, out, size, iv, 4 );

 // тот же результат может быть получен за несколько вызовов
  ak_bckey_context_ctr( &key, in, out, 16, iv, 4 );
  ak_bckey_context_ctr( &key, in+16, out+16, 16, NULL, 0 );
  ak_bckey_context_ctr( &key, in+32, out+32, size-32, NULL, 0 );
        // для того, чтобы использовать внутреннее значение синхропосылки,
        //              мы передаем нулевые значения последних параметров

\endcode

 В приведенном выше фрагменте исходный буффер сначала зашифровывается за один вызов функции,
 а потом фрагментами, длина которых кратна длине блока используемого алгоритма блочного шифрования.
 Результаты зашифрования должны совпадать в обоих случаях. Указанное поведение функции позволяет
 зашифровывать данные в случае, когда они поступают фрагментами, например из сети, или когда хранение
 данных полностью в оперативной памяти нецелесообразно (например, шифрование больших файлов).

    @param bkey Контекст ключа алгоритма блочного шифрования, на котором происходит
    зашифрование или расшифрование информации.
    @param in Указатель на область памяти, где хранятся входные (открытые) данные.
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с `in`).
    @param size Размер зашировываемых данных (в байтах).
    @param iv Указатель на произвольную область памяти - синхропосылку. Область памяти, на
    которую указывает `iv` не изменяется.
    @param iv_size Длина синхропосылки в байтах. Согласно  стандарту ГОСТ Р 34.13-2015 длина
    синхропосылки должна быть ровно в два раза меньше, чем длина блока, то есть 4 байта для Магмы
    и 8 байт для Кузнечика. Значение `iv_size`, отличное от указанных, приведет к возникновению
    ошибки.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_ctr( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                                     ak_pointer iv, size_t iv_size )
{
  int error = ak_error_ok;
  ak_int64 blocks = (ak_int64)size/bkey->bsize,
             tail = (ak_int64)size%bkey->bsize;
  ak_uint64 yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                   "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.value.counter < ( blocks + ( tail > 0 )))
    return ak_error_message( ak_error_low_key_resource,
                                                    __func__ , "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= ( blocks + ( tail > 0 ));

 /* выбираем, как вычислять синхропосылку */
  if(( iv == NULL ) || ( iv_size == 0 )) { /* запрос на использование внутреннего значения */
    if( ak_buffer_is_assigned( &bkey->ivector ) != ak_true )
      return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                  "first calling function with undefined value of initial vector" );
    if( bkey->key.flags&bckey_flag_not_ctr )
      return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                              "secondary calling function with undefined value of initial vector" );
  } else {
     size_t halfsize = bkey->bsize >> 1 ;

    /* проверяем длину синхропосылки (если меньше половины блока, то плохо)
        если больше - то лишнее не используется */
     if( iv_size < halfsize )
       return ak_error_message( ak_error_wrong_iv_length, __func__,
                                                              "incorrect length of initial value" );
    /* выделяем память под буффер и помещаем в него значение */
     if(( error = ak_buffer_set_size( &bkey->ivector, bkey->bsize )) != ak_error_ok )
       return ak_error_message( error, __func__ , "incorrect momory allocation for internal vector" );

     memset( bkey->ivector.data, 0, bkey->ivector.size );
      /* слишком большое значение iv_size может привести к выходу за границы памяти,
                                                 выделенной под переменную ivector->data */
     memcpy( ((ak_uint8 *)bkey->ivector.data) + halfsize, iv, ak_min( halfsize, iv_size ));

    /* снимаем значение флага */
     if( bkey->key.flags&bckey_flag_not_ctr ) bkey->key.flags ^= bckey_flag_not_ctr;
    }

 /* обработка основного массива данных (кратного длине блока) */
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита */
      while( blocks > 0 ) {
        #ifndef LIBAKRYPT_LITTLE_ENDIAN
          ak_uint64 tmp = bswap_64( ((ak_uint64 *)bkey->ivector.data)[0] );
        #endif
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0];
          outptr++; inptr++;
        #ifdef LIBAKRYPT_LITTLE_ENDIAN
          ((ak_uint64 *)bkey->ivector.data)[0]++;
        #else
          ((ak_uint64 *)bkey->ivector.data)[0] = bswap_64( ++tmp );
        #endif
        --blocks;
      };
    break;

    case 16: /* шифр с длиной блока 128 бит */
      while( blocks > 0 ) {
        #ifndef LIBAKRYPT_LITTLE_ENDIAN
          ak_uint64 tmp = bswap_64( ((ak_uint64 *)bkey->ivector.data)[0] );
        #endif
          bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
          *outptr = *inptr ^ yaout[0]; outptr++; inptr++;
          *outptr = *inptr ^ yaout[1]; outptr++; inptr++;
        #ifdef LIBAKRYPT_LITTLE_ENDIAN
          ((ak_uint64 *)bkey->ivector.data)[0]++;
        #else
          ((ak_uint64 *)bkey->ivector.data)[0] = bswap_64( ++tmp );
        #endif                                      /* здесь мы не учитываем знак переноса
                                                     потому что объем данных на одном ключе не должен превышать
                                                     2^64 блоков (контролируется через ресурс ключа) */
        --blocks;
      };
    break;

    default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
  }

 /* обрабатываем хвост сообщения */
  if( tail ) {
    size_t i;
    bkey->encrypt( &bkey->key, bkey->ivector.data, yaout );
    for( i = 0; i < tail; i++ ) /* теперь мы гаммируем tail байт, используя для этого
                                   старшие байты (most significant bytes) зашифрованного счетчика */
        ( (ak_uint8*)outptr )[i] =
           ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[bkey->bsize-tail+i];
   /* запрещаем дальнейшее использование xcrypt на данном значении синхропосылки,
                                           поскольку обрабатываемые данные не кратны длине блока. */
    memset( bkey->ivector.data, 0, bkey->ivector.size );
    bkey->key.flags |= bckey_flag_not_ctr;
  }

 /* перемаскируем ключ */
  if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of secret key" );

 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Контекст ключа алгоритма блочного шифрования.
    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
 /* ----------------------------------------------------------------------------------------------- */
 static int ak_acpkm( ak_bckey bkey )
{

  bkey->key.unmask(&bkey->key);
  ak_uint64 *new_key = bkey->key.key.alloc(bkey->key.key.size);
  ak_uint64 *new_key_for_set = new_key;
  ak_uint64 *D = (ak_uint64 *) acpkm_D;
  for( size_t i=0; i < bkey->key.key.size; i+=bkey->bsize ) {
    switch( bkey->bsize ) {
      case  8: /* шифр с длиной блока 64 бита */
        bkey->encrypt( &bkey->key, D++, new_key++ );
        break;
      case 16: /* шифр с длиной блока 128 бит */
        bkey->encrypt( &bkey->key, D, new_key );
        D += 2; new_key += 2;
        break;
      default: return ak_error_message( ak_error_wrong_block_cipher,
                                            __func__ , "incorrect block size of block cipher key" );
    }
  }

  if (ak_bckey_context_set_key(bkey, new_key_for_set, bkey->key.key.size, ak_true) != ak_error_ok)
    return ak_error_message( ak_error_key_usage,
                            __func__ , "can't replace key by new using acpkm" );
  bkey->key.key.free(new_key_for_set);
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Контекст ключа алгоритма блочного шифрования.
    @param in Указатель на область памяти, где хранятся входные (зашифровываемые) данные
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах). Для режима простой замены
    длина зашифровываемых данных должна быть кратна длине блока.
    @param section_size длина секции (в байтах), которая шифруется на одном ключе
    @param iv имитовставка
    @param iv_size длина имитовставки

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_ctr_acpkm( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                  size_t section_size, ak_pointer iv, size_t iv_size)
{
  int error = ak_error_ok;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
  ak_uint64 out_buf[2];

  /* выполняем проверку размера входных данных */
   if( size%bkey->bsize != 0 )
     return ak_error_message( ak_error_wrong_block_cipher_length,
                             __func__ , "the length of input data is not divided by block length" );
  /* выполняем проверку размера входных данных */
   if( section_size%bkey->bsize != 0 )
     return ak_error_message( ak_error_wrong_block_cipher_length,
                             __func__ , "the length of section is not divided by block length" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );

  ak_uint64 ctr[2] = {0x0, 0x0};
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита */
      if (iv_size != 4)
        return ak_error_message( ak_error_wrong_block_cipher_length,
                                __func__ , "the length of initialization vector is incorrect" );
      ctr[0] = ((ak_uint64 *) iv)[0] << 32;
    break;

    case 16: /* шифр с длиной блока 128 бит */
      if (iv_size != 8)
        return ak_error_message( ak_error_wrong_block_cipher_length,
                                __func__ , "the length of initialization vector is incorrect" );
      ctr[1] = ((ak_uint64 *) iv)[0];
    break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
  }

  for( size_t sections_encoded = 0; sections_encoded < size; sections_encoded += section_size ) {
    size_t encoding_data_size = section_size < (size - sections_encoded) ? section_size : (size - sections_encoded);
    ak_int64 blocks = (ak_uint64) encoding_data_size/bkey->bsize;
   /* уменьшаем значение ресурса ключа */
    if( bkey->key.resource.value.counter < blocks )
      return ak_error_message( ak_error_low_key_resource,
                                                     __func__ , "low resource of block cipher key" );
     else bkey->key.resource.value.counter -= blocks;


   /* теперь приступаем к зашифрованию данных */
    switch( bkey->bsize ) {
      case  8: /* шифр с длиной блока 64 бита */
        do {
          bkey->encrypt( &bkey->key, ctr, out_buf );
          ctr[0] += 1;
          ((ak_uint64 *) outptr)[0] = ((ak_uint64 *) inptr)[0] ^ out_buf[0];
          outptr += 1; inptr += 1;
        } while( --blocks > 0 );
      break;

      case 16: /* шифр с длиной блока 128 бит */
        do {
          bkey->encrypt( &bkey->key, ctr, out_buf );
          ctr[0] += 1; if ( ctr[0] == 0 ) ctr[1] += 1;
          ((ak_uint64 *) outptr)[0] = ((ak_uint64 *) inptr)[0]  ^ out_buf[0];
          ((ak_uint64 *) outptr)[1] = ((ak_uint64 *) inptr)[1]  ^ out_buf[1];
          inptr += 2; outptr += 2;
        } while( --blocks > 0 );
      break;
      default: return ak_error_message( ak_error_wrong_block_cipher,
                                            __func__ , "incorrect block size of block cipher key" );
    }

   /*берем следующий ключ*/
    if( (error = ak_acpkm(bkey)) != ak_error_ok )
      return ak_error_message( error, __func__ , "error when generate new key" );
  }

 /* перемаскируем ключ */
  if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong remasking of secret key" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданной области памяти фиксированного размера.

   @param bkey Ключ алгоритма блочного шифрования, используемый для выработки имитовставки.
   Ключ должен быть создан и определен.
   @param in Указатель на входные данные для которых вычисляется имитовставка.
   @param size Размер входных данных в байтах.
   @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
   Размер выделяемой памяти должен совпадать с длиной блока используемого алгоритма
   блочного шифрования. Указатель out может принимать значение NULL.

   @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
   возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
   ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
   ak_error_get_value().                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_bckey_context_omac( ak_bckey bkey, ak_pointer in, size_t size, ak_pointer out )
{
  ak_pointer pout = NULL;
  ak_buffer result = NULL;
  ak_int64 i = 0,
 #ifdef LIBAKRYPT_LITTLE_ENDIAN
           one64[2] = { 0x02, 0x00 },
 #else
           one64[2] = { 0x0200000000000000LL, 0x00LL },
 #endif
           blocks = (ak_int64)size/bkey->bsize,
           tail = (ak_int64)size%bkey->bsize;
  ak_uint64 yaout[2], akey[2], *inptr = (ak_uint64 *)in;

 /* проверяем, что длина данных больше нуля */
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__, "using a data with zero length" );
    return NULL;
  }

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true ) {
    ak_error_message( ak_error_wrong_key_icode, __func__,
                                                  "incorrect integrity code of secret key value" );
    return NULL;
  }

 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.value.counter < ( blocks + ( tail > 0 ))) {
    ak_error_message( ak_error_low_key_resource, __func__ , "low resource of block cipher key" );
    return NULL;
  } else bkey->key.resource.value.counter -= ( blocks + ( tail > 0 )); /* уменьшаем ресурс ключа */

  memset( akey, 0, sizeof( akey ));
  memset( yaout, 0, sizeof( yaout ));
  if( !tail ) { tail = bkey->bsize; blocks--; } /* последний блок всегда существует */

 /* основной цикл */
  switch( bkey->bsize ) {
   case  8 :
          /* здесь длина блока равна 64 бита */
            for( i = 0; i < blocks; i++, inptr++ ) {
               yaout[0] ^= inptr[0];
               bkey->encrypt( &bkey->key, yaout, yaout );
            }

          /* теперь ключи для завершения алгоритма */
            bkey->encrypt( &bkey->key, akey, akey );
            ak_gf64_mul( akey, akey, one64 );

            if( tail < bkey->bsize ) {
              ak_gf64_mul( akey, akey, one64 );
              ((ak_uint8 *)akey)[tail] ^= 0x80;
            }

          /* теперь шифруем последний блок */
            akey[0] ^= yaout[0];
            for( i = 0; i < tail; i++ ) ((ak_uint8 *)akey)[i] ^= ((ak_uint8 *)inptr)[i];
            bkey->encrypt( &bkey->key, akey, akey );
          break;

   case 16 :
          /* здесь длина блока равна 128 бита */
            for( i = 0; i < blocks; i++, inptr += 2 ) {
               yaout[0] ^= inptr[0];
               yaout[1] ^= inptr[1];
               bkey->encrypt( &bkey->key, yaout, yaout );
            }
          /* вырабатываем ключи для завершения алгортма */
            bkey->encrypt( &bkey->key, akey, akey );
            ak_gf128_mul( akey, akey, one64 );
            if( tail < bkey->bsize ) {
              ak_gf128_mul( akey, akey, one64 );
              ((ak_uint8 *)akey)[tail] ^= 0x80;
            }
          /* теперь шифруем последний блок*/
            akey[0] ^= yaout[0]; akey[1] ^= yaout[1];
            for( i = 0; i < tail; i++ ) ((ak_uint8 *)akey)[i] ^= ((ak_uint8 *)inptr)[i];
            bkey->encrypt( &bkey->key, akey, akey );
          break;
  }

 /* определяем указатель на область памяти, в которую будет помещен результат вычислений */
  if( out != NULL ) pout = out;
   else {
     if(( result = ak_buffer_new_size( bkey->bsize )) != NULL ) pout = result->data;
      else ak_error_message( ak_error_get_value( ), __func__ , "wrong creation of result buffer" );
   }
 /* копируем нужную часть результирующего массива или выдаем сообщение об ошибке */
  if( pout != NULL ) memcpy( pout, akey, bkey->bsize );
    else ak_error_message( ak_error_out_of_memory, __func__ ,
                                                 "incorrect memory allocation for result buffer" );
 return result;
}

 static int ak_get_next_key( ak_bckey bkey, ak_uint64 ctr[2], ak_uint64 ki[4], ak_uint64 ki1[2], ak_uint64 *T, ak_uint64 Ts)
{
  ak_uint64 blocks = 1 + (ak_uint64) bkey->key.key.size / bkey->bsize;

  for(ak_uint64 i=0; i < blocks; ++i) {
    switch( bkey->bsize ) {
      case  8: /* шифр с длиной блока 64 бита */
        bkey->encrypt( &bkey->key, ctr, i+1 == blocks ? ki1 : ki + 3 - i );
        ctr[0] += 1;
      break;

      case 16: /* шифр с длиной блока 128 бит */
        bkey->encrypt( &bkey->key, ctr, i+1 == blocks ? ki1 : ki + 2 - 2*i );
        ctr[0] += 1; if ( ctr[0] == 0 ) ctr[1] += 1;
      break;
      default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
    }
    *T += bkey->bsize;
    if( *T == Ts) {
      ak_acpkm(bkey);
      *T = 0;
    }
  }
}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданной области памяти фиксированного размера.

   @param bkey Ключ алгоритма блочного шифрования, используемый для выработки имитовставки.
   Ключ должен быть создан и определен.
   @param in Указатель на входные данные для которых вычисляется имитовставка.
   @param size Размер входных данных в байтах.
   @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
   Размер выделяемой памяти должен совпадать с длиной блока используемого алгоритма
   блочного шифрования. Указатель out может принимать значение NULL.
   @param длина секции, которая шифруется на одном ключе
   @param Ts частота с которой новый ключ получается с помощью функции acpkm

   @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
   возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
   ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
   ak_error_get_value().                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_omac_acpkm( ak_bckey bkey, ak_pointer in, size_t size, ak_pointer out, size_t section_size, size_t Ts )
{
 /* проверяем, что длина данных больше нуля */
  if( !size ) {
    return ak_error_message( ak_error_zero_length, __func__, "using a data with zero length" );
  }

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true ) {
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                  "incorrect integrity code of secret key value" );
  }

 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.value.counter < section_size/bkey->bsize ) {
    return ak_error_message( ak_error_low_key_resource, __func__ , "low resource of block cipher key" );
  } else bkey->key.resource.value.counter -= section_size/bkey->bsize; /* уменьшаем ресурс ключа */

  bkey->key.unmask(&bkey->key);
  ak_uint64 gen_key[4];
  memcpy(gen_key, bkey->key.key.data, bkey->key.key.size);
  ak_uint64 i = 0;
  ak_int64 blocks = (ak_int64)size/bkey->bsize;
  ak_int64 tail = (ak_int64)size%bkey->bsize;
  ak_uint64 key[4], key1[2], *inptr = (ak_uint64 *)in;
  ak_uint64 T = 0;
  ak_uint64 C[2] = {0, 0};


  ak_uint64 last_block[2] = {0, 0};
  if (tail) {
    memcpy(((ak_uint8 *)last_block) + bkey->bsize - tail, ((ak_uint8 *) in) + blocks * bkey->bsize, tail);
    switch( bkey->bsize ) {
      case  8: /* шифр с длиной блока 64 бита */
        last_block[0] += (ak_uint64) 0x1 << (8*(bkey->bsize - tail) - 1);
      break;
      case 16: /* шифр с длиной блока 128 бит */
        if (tail > 7)
          last_block[0] += (ak_uint64) 0x1 << (8*(bkey->bsize - tail) - 1);
        else {
          last_block[0] += 0x0;
          last_block[1] += (ak_uint64) 0x1 << (8*(bkey->bsize - tail - 8) - 1);
        }
      break;
      default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
    }
  } else {
    memcpy(last_block, ((ak_uint8 *)in) + (blocks - 1) * bkey->bsize, bkey->bsize );
  }

  ak_uint64 ctr[2] = {0x0, 0x0};
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита */
      ctr[0] = 0xffffffff00000000;
    break;
    case 16: /* шифр с длиной блока 128 бит */
      ctr[1] = 0xffffffffffffffff;
    break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                        __func__ , "incorrect block size of block cipher key" );
  }

  for( i=0; bkey->bsize + i < size ; i+= bkey->bsize) {
    if( i%section_size == 0 ) {
      ak_bckey_context_set_key(bkey, gen_key, bkey->key.key.size, ak_true);
      ak_get_next_key(bkey, ctr, key, key1, &T, Ts);
      bkey->key.unmask(&bkey->key);
      memcpy(gen_key, bkey->key.key.data, bkey->key.key.size);
      ak_bckey_context_set_key(bkey, key, bkey->key.key.size, ak_true);
    }

    switch( bkey->bsize ) {
      case  8: /* шифр с длиной блока 64 бита */
        C[0] ^= inptr[0];
        bkey->encrypt( &bkey->key, C, C );
        inptr += 1;
      break;
      case 16: /* шифр с длиной блока 128 бит */
        C[0] ^= inptr[0];
        C[1] ^= inptr[1];
        bkey->key.unmask(&bkey->key);
        bkey->encrypt( &bkey->key, C, C );
        inptr += 2;
      break;
      default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
    }
  }

  if( i%section_size == 0 ) {
    ak_bckey_context_set_key(bkey, gen_key, bkey->key.key.size, ak_true);
    ak_get_next_key(bkey, ctr, key, key1, &T, Ts);
    bkey->key.unmask(&bkey->key);
    memcpy(gen_key, bkey->key.key.data, bkey->key.key.size);
    ak_bckey_context_set_key(bkey, key, bkey->key.key.size, ak_true);
  }
  if ( tail ) {
    switch( bkey->bsize ) {
      case  8: /* шифр с длиной блока 64 бита */
        if( key1[0] & 0x8000000000000000 ) {
          key1[0] = (key1[0] << 1) ^ 0x1b ;
        } else {
          key1[0] = key1[0] << 1;
        }
      break;
      case 16: /* шифр с длиной блока 128 бит */
        if( key1[1] & 0x8000000000000000 ) {
          key1[1] = (key1[1] << 1) + (key1[0] & 0x8000000000000000);
          key1[0] = (key1[0] << 1) ^ 0x87;
        } else {
          key1[1] = (key1[1] << 1) + (key1[0] & 0x8000000000000000);
          key1[0] = key1[0] << 1;
        }
      break;
      default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
    }
  }

  last_block[0] ^= C[0] ^ key1[0];
  last_block[1] ^= C[1] ^ key1[1];

  bkey->encrypt(&bkey->key, last_block, out );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  \example test-internal-bckey01.c                                                              */
/*!  \example test-internal-bckey02.c                                                              */
/*!  \example test-internal-bckey03.c                                                              */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_bckey.c  */
/* ----------------------------------------------------------------------------------------------- */
