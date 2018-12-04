/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mac.c                                                                                  */
/*  - содержит функции, реализующие аутентифицированное шифрование
      и различные режимы его применения.                                                           */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mgm.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует значение счетчика, отвечающего за вычисление значений (множителей),
    используемых для вычисления имитовставки (счетчик H).

    В ходе выполнения функции выполняются проверки корректности переданных данных.

    @param ctx Контекст внутреннего состояния алгоритма
    @param authenticationKey Ключ блочного алгоритма шифрования, используемый для шифрования
    текущего значения счетчика
    @param iv Синхропосылка.
    \b ВНимание! Для работы используются только \f$ n-1 \f$ младший бит. Старший бит принудительно
    получает значение, равное 1.

    @param iv_size Длин синхропосылки в байтах. Длина должна быть отлична от нуля и может быть
    меньше, чем длина блока (в этом случае синхропосылка дополняется нулями в старших байтах).

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_authentication_clean( ak_mgm_ctx ctx,
                            ak_bckey authenticationKey, const ak_pointer iv, const size_t iv_size )
{
 ak_uint8 ivector[16]; /* временное значение синхропосылки */

 if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to internal mgm context");
 if( authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");
 if( authenticationKey->bsize > 16 ) return ak_error_message( ak_error_wrong_length,
                                                 __func__, "using key with very large block size" );
 /* инициализация значением и ресурс */
 if(( authenticationKey->key.flags&skey_flag_set_key ) == 0 )
   return ak_error_message( ak_error_key_value, __func__,
                                         "using block cipher key context with undefined key value");
 if( authenticationKey->key.resource.counter <= 0 )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");

 if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
 if( iv_size > authenticationKey->bsize ) return ak_error_message( ak_error_wrong_length,
                                           __func__, "using initial vector with unexpected length");
 /* обнуляем необходимое */
  memset( &ctx, 0, sizeof( struct mgm_ctx )); /* очищаем по максимуму */
  memcpy( ivector, iv, iv_size ); /* копируем нужное количество байт */
 /* принудительно устанавливаем старший бит в 1 */
  // ivector[iv_size-1] = ( ivector[iv_size-1]&0x7F ) ^ 0x80;
  ivector[authenticationKey->ivector.size-1] = ( ivector[authenticationKey->ivector.size-1]&0x7F ) ^ 0x80;

 /* зашифровываем необходимое и удаляемся */
  authenticationKey->encrypt( &authenticationKey->key, ivector, &ctx->zcount );
  authenticationKey->key.resource.counter--;

 return ak_error_ok;
}


///* ----------------------------------------------------------------------------------------------- */
//#define astep64(DATA)  authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &ctx->h ); \
//                       ak_gf64_mul( &ctx->mulres, &ctx->h, (DATA) ); \
//                       ctx->sum.q[0] ^= ctx->mulres.q[0]; \
//                       ctx->zcount.w[1]++;

//#define astep128(DATA) authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &ctx->h ); \
//                       ak_gf128_mul( &ctx->mulres, &ctx->h, (DATA) ); \
//                       ctx->sum.q[0] ^= ctx->mulres.q[0]; \
//                       ctx->sum.q[1] ^= ctx->mulres.q[1]; \
//                       ctx->zcount.q[1]++;

///* ----------------------------------------------------------------------------------------------- */
///*! Функция обрабатывает очередной блок дополнительных данных и
//    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
//    выработки имитовставки. Если длина входных данных не кратна длине блока алгоритма шифрования,
//    то это воспринимается как конец процесса обновления (после этого вызов функции блокируется).

//    Если данные кратны длине блока, то блокировки не происходит --
//    блокировка происходит в момент вызова функций обработки зашифровываемых данных.

//    @param ctx Контекст внутреннего состояния алгоритма
//    @param authenticationKey Ключ блочного алгоритма шифрования, используемый для
//    шифрования текущего значения счетчика
//    @param adata
//    @param adata_size

//    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
//    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
//    или возникла ошибка, то возвращается код ошибки                                                */
///* ----------------------------------------------------------------------------------------------- */
// int ak_mgm_context_authentication_update( ak_mgm_ctx ctx,
//                      ak_bckey authenticationKey, const ak_pointer adata, const size_t adata_size )
//{
//  ak_uint8 temp[16], *aptr = (ak_uint8 *)adata;
//  size_t absize = authenticationKey->ivector.size;
//  ak_int64 resource = 0,
//           tail = (ak_int64) adata_size%absize,
//           blocks = (ak_int64) adata_size/absize;

// /* проверка возможности обновления */
//  if( ctx->flags&0x1 ) return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
//                                               "using function with previously closed mgm context");
// /* ни чего не задано => ни чего не обрабатываем */
//  if(( adata == NULL ) || ( adata_size == 0 )) return ak_error_ok;

// /* проверка ресурса ключа */
//  if( authenticationKey->key.resource.counter <= (resource = blocks + (tail > 0)))
//   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
//  else authenticationKey->key.resource.counter -= resource;

// /* теперь основной цикл */
// if( absize == 16 ) { /* обработка 128-битным шифром */

//   ctx->abitlen += ( blocks  << 7 );
//   for( ; blocks > 0; blocks--, aptr += 16 ) { astep128( aptr );  }
//   if( tail ) {
//    memset( temp, 0, 16 );
//    memcpy( temp+absize-tail, aptr, (size_t)tail );
//    astep128( temp );
//  /* закрываем добавление ассоциированных данных */
//    ctx->aflag |= 0x1;
//    ctx->abitlen += ( tail << 3 );
//  }
// } else { /* обработка 64-битным шифром */

//   ctx->abitlen += ( blocks << 6 );
//   for( ; blocks > 0; blocks--, aptr += 8 ) { astep64( aptr ); }
//   if( tail ) {
//    memset( temp, 0, 8 );
//    memcpy( temp+absize-tail, aptr, (size_t)tail );
//    astep64( temp );
//   /* закрываем добавление ассоциированных данных */
//    ctx->aflag |= 0x1;
//    ctx->abitlen += ( tail << 3 );
//  }
// }

// return ak_error_ok;
//}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mgm.c  */
/* ----------------------------------------------------------------------------------------------- */
