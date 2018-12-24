/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mac.c                                                                                  */
/*  - содержит функции, реализующие аутентифицированное шифрование
      и различные режимы его применения.                                                           */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mgm.h>

/* ----------------------------------------------------------------------------------------------- */
 #define ak_mgm_assosiated_data_bit  (0x1)
 #define ak_mgm_encrypted_data_bit   (0x2)

 #define ak_mgm_set_bit( x, n ) ( (x) = ((x)&(0xFFFFFFFF^(n)))^(n) )

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
 if(( iv_size == 0 ) || ( iv_size > authenticationKey->bsize ))
   return ak_error_message( ak_error_wrong_length,
                                           __func__, "using initial vector with unexpected length");
 /* обнуляем необходимое */
  ctx->abitlen = 0;
  ctx->flags = 0;
  ctx->pbitlen = 0;
  memset( ctx->sum.b, 0, 16 );
  memset( ctx->sum.b, 0, 16 );
  memset( ctx->sum.b, 0, 16 );

  memcpy( ivector, iv, iv_size ); /* копируем нужное количество байт */
 /* принудительно устанавливаем старший бит в 1 */
  // ivector[iv_size-1] = ( ivector[iv_size-1]&0x7F ) ^ 0x80;
  ivector[authenticationKey->bsize-1] = ( ivector[authenticationKey->bsize-1]&0x7F ) ^ 0x80;

 /* зашифровываем необходимое и удаляемся */
  authenticationKey->encrypt( &authenticationKey->key, ivector, &ctx->zcount );
  authenticationKey->key.resource.counter--;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
#define astep64(DATA)  authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &h ); \
                       ak_gf64_mul( &h, &h, (DATA) ); \
                       ctx->sum.q[0] ^= h.q[0]; \
                       ctx->zcount.w[1]++;

#define astep128(DATA) authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &h ); \
                       ak_gf128_mul( &h, &h, (DATA) ); \
                       ctx->sum.q[0] ^= h.q[0]; \
                       ctx->sum.q[1] ^= h.q[1]; \
                       ctx->zcount.q[1]++;

/* ----------------------------------------------------------------------------------------------- */
/*! Функция обрабатывает очередной блок дополнительных данных и
    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    выработки имитовставки. Если длина входных данных не кратна длине блока алгоритма шифрования,
    то это воспринимается как конец процесса обновления (после этого вызов функции блокируется).

    Если данные кратны длине блока, то блокировки не происходит --
    блокировка происходит в момент вызова функций обработки зашифровываемых данных.

    @param ctx Контекст внутреннего состояния алгоритма
    @param authenticationKey Ключ блочного алгоритма шифрования, используемый для
    шифрования текущего значения счетчика
    @param adata
    @param adata_size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_authentication_update( ak_mgm_ctx ctx,
                      ak_bckey authenticationKey, const ak_pointer adata, const size_t adata_size )
{
  ak_uint128 h;
  ak_uint8 temp[16], *aptr = (ak_uint8 *)adata;
  ssize_t absize = ( ssize_t ) authenticationKey->bsize;
  ssize_t resource = 0,
          tail = ( ssize_t ) adata_size%absize,
          blocks = ( ssize_t ) adata_size/absize;

 /* проверка возможности обновления */
  if( ctx->flags&ak_mgm_assosiated_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                                  "attemp to update previously closed mgm context");
 /* ни чего не задано => ни чего не обрабатываем */
  if(( adata == NULL ) || ( adata_size == 0 )) return ak_error_ok;

 /* проверка ресурса ключа */
  if( authenticationKey->key.resource.counter <= (resource = blocks + (tail > 0)))
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else authenticationKey->key.resource.counter -= resource;

 /* теперь основной цикл */
 if( absize == 16 ) { /* обработка 128-битным шифром */

   ctx->abitlen += ( blocks  << 7 );
   for( ; blocks > 0; blocks--, aptr += 16 ) { astep128( aptr );  }
   if( tail ) {
    memset( temp, 0, 16 );
    memcpy( temp+absize-tail, aptr, (size_t)tail );
    astep128( temp );
  /* закрываем добавление ассоциированных данных */
    ak_mgm_set_bit( ctx->flags, ak_mgm_assosiated_data_bit );
    ctx->abitlen += ( tail << 3 );
  }
 } else { /* обработка 64-битным шифром */

   ctx->abitlen += ( blocks << 6 );
   for( ; blocks > 0; blocks--, aptr += 8 ) { astep64( aptr ); }
   if( tail ) {
    memset( temp, 0, 8 );
    memcpy( temp+absize-tail, aptr, (size_t)tail );
    astep64( temp );
   /* закрываем добавление ассоциированных данных */
    ak_mgm_set_bit( ctx->flags, ak_mgm_assosiated_data_bit );
    ctx->abitlen += ( tail << 3 );
  }
 }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция завершает вычисления и возвращает значение имитовставки.

   @param ctx
   @param authenticationKey
   @param out
   @param out_size

   @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
   возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
   ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
   ak_error_get_value().                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_mgm_context_authentication_finalize( ak_mgm_ctx ctx,
                                 ak_bckey authenticationKey, ak_pointer out, const size_t out_size )
{
  ak_uint128 temp, h;
  ak_pointer pout = NULL;
  ak_buffer result = NULL;
  size_t absize = authenticationKey->bsize;

 /* проверка запрашиваемой длины iv */
  if(( out_size == 0 ) || ( out_size > absize )) {
    ak_error_message( ak_error_wrong_length, __func__, "unexpected length of integrity code" );
    return NULL;
  }
 /* проверка длины блока */
  if( absize > 16 ) {
    ak_error_message( ak_error_wrong_length, __func__, "using key with large block size" );
    return NULL;
  }

 /* традиционная проверка ресурса */
  if( authenticationKey->key.resource.counter <= 0 ) {
    ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
    return NULL;
  } else authenticationKey->key.resource.counter--;

 /* закрываем добавление шифруемых данных */
   ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );

 /* формируем последний вектор из длин */
  if(  absize&0x10 ) {
    temp.q[0] = ( ak_uint64 )ctx->pbitlen;
    temp.q[1] = ( ak_uint64 )ctx->abitlen;
    astep128( temp.b );

  } else { /* теперь тоже самое, но для 64-битного шифра */

     if(( ctx->abitlen > 0xFFFFFFFF ) || ( ctx->pbitlen > 0xFFFFFFFF )) {
       ak_error_message( ak_error_overflow, __func__, "using an algorithm with very long data" );
       return NULL;
     }
     temp.w[0] = (ak_uint32) ctx->pbitlen;
     temp.w[1] = (ak_uint32) ctx->abitlen;
     astep64( temp.b );
  }

 /* определяем указатель на область памяти, в которую будет помещен результат вычислений */
  if( out != NULL ) pout = out;
   else {
     if(( result =
              ak_buffer_new_size( authenticationKey->bsize )) != NULL ) pout = result->data;
      else ak_error_message( ak_error_get_value( ), __func__ , "wrong creation of result buffer" );
   }

 /* последнее шифрование и завершение работы */
  if( pout != NULL ) {
    authenticationKey->encrypt( &authenticationKey->key, &ctx->sum, &ctx->sum );
    memcpy( pout, ctx->sum.b+absize-out_size, out_size );
  } else ak_error_message( ak_error_out_of_memory, __func__ ,
                                                "incorrect memory allocation for result buffer" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует значение внутренних переменных алгоритма MGM, участвующих в процессе
    шифрования.

    @param ctx
    @param encryptionKey
    @param iv
    @param iv_size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_encryption_clean( ak_mgm_ctx ctx,
                            ak_bckey encryptionKey, const ak_pointer iv, const size_t iv_size )
{
 ak_uint8 ivector[16]; /* временное значение синхропосылки */

 if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to internal mgm context");
 if( encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");
 if( encryptionKey->bsize > 16 ) return ak_error_message( ak_error_wrong_length,
                                                      __func__, "using key with large block size" );
 /* инициализация значением и ресурс */
 if(( encryptionKey->key.flags&skey_flag_set_key ) == 0 )
           return ak_error_message( ak_error_key_value, __func__,
                                               "using secret key context with undefined key value");
 if( encryptionKey->key.resource.counter <= 0 )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");

 if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
 if(( iv_size == 0 ) || ( iv_size > encryptionKey->bsize ))
   return ak_error_message( ak_error_wrong_length,
                                           __func__, "using initial vector with unexpected length");
 /* обнуляем необходимое */
  ctx->flags &= ak_mgm_assosiated_data_bit;
  ctx->pbitlen = 0;
  memset( &ctx->ycount, 0, 16 );
  memset( ivector, 0, 16 );
  memcpy( ivector, iv, iv_size ); /* копируем нужное количество байт */
 /* принудительно устанавливаем старший бит в 0 */
  ivector[iv_size-1] = ( ivector[iv_size-1]&0x7F );

 /* зашифровываем необходимое и удаляемся */
  encryptionKey->encrypt( &encryptionKey->key, ivector, &ctx->ycount );
  encryptionKey->key.resource.counter--;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
#define estep64  encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e ); \
                 outp[0] = inp[0] ^ e.q[0]; \
                 ctx->ycount.w[0]++;

#define estep128 encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e ); \
                 outp[0] = inp[0] ^ e.q[0]; \
                 outp[1] = inp[1] ^ e.q[1]; \
                 ctx->ycount.q[0]++;

/* ----------------------------------------------------------------------------------------------- */
/*! Функция зашифровывает очередной фрагмент данных и
    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    шифрования с одновременной выработкой имитовставки. Если длина входных данных не кратна длине
    блока алгоритма шифрования, то это воспринимается как конец процесса шифрования/обновления
    (после этого вызов функции блокируется).

    @param ctx
    @param encryptionKey
    @param authenticationKey
    @param in
    @param out
    @param size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_encryption_update( ak_mgm_ctx ctx, ak_bckey encryptionKey,
         ak_bckey authenticationKey, const ak_pointer in, ak_pointer out, const size_t size )
{
  ak_uint128 e, h;
  ak_uint8 temp[16];
  size_t i = 0, absize = encryptionKey->bsize;
  ak_uint64 *inp = (ak_uint64 *)in, *outp = (ak_uint64 *)out;
  size_t resource = 0,
         tail = size%absize,
         blocks = size/absize;

 /* принудительно закрываем обновление ассоциированных данных */
  ak_mgm_set_bit( ctx->flags, ak_mgm_assosiated_data_bit );
 /* проверяем возможность обновления */
  if( ctx->flags&ak_mgm_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                        "using this function with previously closed aead context");

 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;

 /* проверка ресурса ключа выработки имитовставки */
  if( authenticationKey != NULL ) {
    if( authenticationKey->key.resource.counter <= ( ssize_t )(resource = blocks + (tail > 0)))
      return ak_error_message( ak_error_low_key_resource, __func__,
                                                "using authentication key with low key resource");
    else authenticationKey->key.resource.counter -= resource;
  }

 /* проверка ресурса ключа шифрования */
  if( encryptionKey->key.resource.counter <= ( ssize_t )resource )
   return ak_error_message( ak_error_low_key_resource, __func__,
                                                   "using encryption key with low key resource");
  else encryptionKey->key.resource.counter -= resource;

 /* теперь обработка данных */
  memset( &e, 0, 16 );
  ctx->pbitlen += ( absize*blocks << 3 );
  if( authenticationKey == NULL ) { /* только шифрование (без вычисления имитовставки) */

    if( absize&0x10 ) { /* режим работы для 128-битного шифра */
     /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         estep128;
      }
      /* хвост */
      if( tail ) {
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[16-tail+i];
       /* закрываем добавление шифруемых данных */
        ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
       /* основная часть */
        for( ; blocks > 0; blocks--, inp++, outp++ ) {
           estep64;
        }
       /* хвост */
        if( tail ) {
          encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
          for( i = 0; i < tail; i++ )
             ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[8-tail+i];
         /* закрываем добавление шифруемых данных */
          ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );
          ctx->pbitlen += ( tail << 3 );
        }
      } /* конец шифрования без аутентификации для 64-битного шифра */

  } else { /* основной режим работы => шифрование с одновременной выработкой имитовставки */

     if( absize&0x10 ) { /* режим работы для 128-битного шифра */
      /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         estep128;
         astep128( outp );
      }
      /* хвост */
      if( tail ) {
        memset( temp, 0, 16 );
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[16-tail+i];
        memcpy( temp+16-tail, outp, (size_t)tail );
        astep128( temp );

       /* закрываем добавление шифруемых данных */
        ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
      /* основная часть */
       for( ; blocks > 0; blocks--, inp++, outp++ ) {
          estep64;
          astep64( outp );
       }
       /* хвост */
       if( tail ) {
         memset( temp, 0, 8 );
         encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
         for( i = 0; i < tail; i++ )
            ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[8-tail+i];
         memcpy( temp+8-tail, outp, (size_t)tail );
         astep64( temp );

        /* закрываем добавление шифруемых данных */
         ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );
         ctx->pbitlen += ( tail << 3 );
       }
     } /* конец 64-битного шифра */
  }

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция расшифровывает очередной фрагмент данных и
    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    расшифрования с проверкой имитовставки. Если длина входных данных не кратна длине
    блока алгоритма шифрования, то это воспринимается как конец процесса расшифрования/обновления
    (после этого вызов функции блокируется).

    @param ctx
    @param encryptionKey
    @param authenticationKey
    @param in
    @param out
    @param size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_decryption_update( ak_mgm_ctx ctx, ak_bckey encryptionKey,
         ak_bckey authenticationKey, const ak_pointer in, ak_pointer out, const size_t size )
{
  ak_uint8 temp[16];
  ak_uint128 e, h;
  size_t i = 0, absize = encryptionKey->bsize;
  ak_uint64 *inp = (ak_uint64 *)in, *outp = (ak_uint64 *)out;
  size_t resource = 0,
         tail = size%absize,
         blocks = size/absize;

 /* принудительно закрываем обновление ассоциированных данных */
  ak_mgm_set_bit( ctx->flags, ak_mgm_assosiated_data_bit );
 /* проверяем возможность обновления */
  if( ctx->flags&ak_mgm_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                        "using this function with previously closed aead context");

 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;

 /* проверка ресурса ключа выработки имитовставки */
  if( authenticationKey != NULL ) {
    if( authenticationKey->key.resource.counter <= ( ssize_t )(resource = blocks + (tail > 0)))
      return ak_error_message( ak_error_low_key_resource, __func__,
                                                "using authentication key with low key resource");
    else authenticationKey->key.resource.counter -= resource;
  }

 /* проверка ресурса ключа шифрования */
  if( encryptionKey->key.resource.counter <= ( ssize_t )resource )
   return ak_error_message( ak_error_low_key_resource, __func__,
                                                   "using encryption key with low key resource");
  else encryptionKey->key.resource.counter -= resource;

 /* теперь обработка данных */
  memset( &e, 0, 16 );
  ctx->pbitlen += ( absize*blocks << 3 );
  if( authenticationKey == NULL ) { /* только шифрование (без вычисления имитовставки) */
                                    /* это полная копия кода, содержащегося в функции .. _encryption_ ... */
    if( absize&0x10 ) { /* режим работы для 128-битного шифра */
     /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         estep128;
      }
      /* хвост */
      if( tail ) {
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[16-tail+i];
       /* закрываем добавление шифруемых данных */
        ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
       /* основная часть */
        for( ; blocks > 0; blocks--, inp++, outp++ ) {
           estep64;
        }
       /* хвост */
        if( tail ) {
          encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
          for( i = 0; i < tail; i++ )
             ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[8-tail+i];
         /* закрываем добавление шифруемых данных */
          ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );
          ctx->pbitlen += ( tail << 3 );
        }
      } /* конец шифрования без аутентификации для 64-битного шифра */

  } else { /* основной режим работы => шифрование с одновременной выработкой имитовставки */

     if( absize&0x10 ) { /* режим работы для 128-битного шифра */
      /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         astep128( inp );
         estep128;
      }
      /* хвост */
      if( tail ) {
        memset( temp, 0, 16 );
        memcpy( temp+16-tail, inp, (size_t)tail );
        astep128( temp );
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[16-tail+i];

       /* закрываем добавление шифруемых данных */
        ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
      /* основная часть */
       for( ; blocks > 0; blocks--, inp++, outp++ ) {
          astep64( inp );
          estep64;
       }
       /* хвост */
       if( tail ) {
         memset( temp, 0, 8 );
         memcpy( temp+8-tail, inp, (size_t)tail );
         astep64( temp );
         encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
         for( i = 0; i < tail; i++ )
            ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[8-tail+i];

        /* закрываем добавление шифруемых данных */
         ak_mgm_set_bit( ctx->flags, ak_mgm_encrypted_data_bit );
         ctx->pbitlen += ( tail << 3 );
       }
     } /* конец 64-битного шифра */
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_bckey_check_mgm_length( const size_t asize, const size_t psize, const size_t bsize )
{
 /* требования к размерам:
    - длина ассоциированных данных (в битах) не более 2^n/2
    - длина шифруемых данных (в битах) не более 2^n/2
    - суммарная длина длина данных (в битах) не более 2^n/2  */

  size_t temp, aval = asize << 3, pval = psize << 3;

   if( aval < asize ) return ak_error_message( ak_error_wrong_length, __func__,
                                                        "length of assosiated data is very huge");
   if( pval < psize ) return ak_error_message( ak_error_wrong_length, __func__,
                                                       "total length of plain data is very huge");
   if(( temp = ( aval + pval )) < pval )
     return ak_error_message( ak_error_wrong_length, __func__,
                                        "total length of assosiated and plain data is very huge");

  /* на 32-х битной архитектуре size_t не превосходит 32 бита =>
     длины корректны для Магмы и для Кузнечика

     на 64-х битной архитектуре много может быть только для Магмы => проверяем */
   if(( sizeof ( ak_pointer ) > 4 ) && ( bsize != 16 )) {
     if( aval > 0x0000000100000000LL ) return ak_error_message( ak_error_wrong_length, __func__,
                                                       "length of assosiated data is very large");
     if( pval > 0x0000000100000000LL ) return ak_error_message( ak_error_wrong_length, __func__,
                                                            "length of plain data is very large");
     if( temp > 0x0000000100000000LL ) return ak_error_message( ak_error_wrong_length, __func__,
                                       "total length of assosiated and plain data is very large");
   }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует режим MGM - режим шифрования для блочного шифра с одновременным вычислением
    имитовставки. На вход функции подаются как данные, подлежащие зашифрованию,
    так и ассоциированные данные, которые не зашифровываются. При этом имитовставка вычисляется
    для всех переданных на вход функции данных.

    Режим MGM может использовать для шифрования и выработки имитовставки два различных ключа -
    в этом случае длины блоков обрабатываемых данных для ключей должны совпадать (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если указатель на ключ шифрования равен NULL, то шифрование данных не производится и указатель на
    зашифровываемые (plain data) и зашифрованные (cipher data) данные \b должен быть равен NULL; длина
    данных (size) также \b должна принимать нулевое значение.

    Если указатель на ключ выработки имитовставки равен NULL, то аутентификация данных не производится.
    В этом случае указатель на ассоциированные данные (associated data) \b должен быть равен NULL,
    указатель на имитовставку (icode) \b должен быть равен NULL, длина дополнительных данных \b должна
    равняться нулю. В этом случае также всегда функция возвращает NULL, а код ошибки должен быть получен
    с помощью вызова функции ak_error_get_value().

    Ситуация, при которой оба указателя на ключ принимают значение NULL воспринимается как ошибка.

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
           может принимать значение NULL;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции; может принимать значение NULL;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на зашифровываеме данные;
    @param out указатель на зашифрованные данные;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, куда будет помещено значение имитовставки;
           память должна быть выделена заранее; указатель может принимать значение NULL.
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;
           если значение icode_size меньше, чем длина блока, то возвращается запрашиваемое количество
           старших байт результата вычислений.

    @return Функция возвращает NULL, если указатель icode не есть NULL, в противном случае
            возвращается указатель на буффер, содержащий результат вычислений. В случае
            возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с
            помощью вызова функции ak_error_get_value().                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_bckey_context_encrypt_mgm( ak_bckey encryptionKey, ak_bckey authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  size_t bs = 0;
  ak_buffer result = NULL;
  int error = ak_error_ok;
  struct mgm_ctx mgm; /* контекст структуры, в которой хранятся промежуточные данные */

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL )) {
    ak_error_message( ak_error_null_pointer, __func__ ,
                               "using null pointers both to encryption and authentication keys" );
    return NULL;
  }
  if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
    if( encryptionKey->bsize != authenticationKey->bsize ) {
      ak_error_message( ak_error_not_equal_data, __func__, "different block sizes for given keys");
      return NULL;
    }
  }
  if( encryptionKey != NULL ) bs = encryptionKey->bsize;
    else bs = authenticationKey->bsize;

 /* проверяем размер входных данных */
  if(( error = ak_bckey_check_mgm_length( adata_size, size, bs )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect length of input data");
    return NULL;
  }

 /* подготавливаем память */
  memset( &mgm, 0, sizeof( struct mgm_ctx ));

 /* в начале обрабатываем ассоциированные данные */
  if( authenticationKey != NULL ) {
    if(( error =
         ak_mgm_context_authentication_clean( &mgm, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator, ak_true );
     return NULL;
    }
    if(( error =
         ak_mgm_context_authentication_update( &mgm, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect hashing of associated data" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator, ak_true );
     return NULL;
    }
  }

 /* потом зашифровываем данные */
  if( encryptionKey != NULL ) {
    if(( error =
         ak_mgm_context_encryption_clean( &mgm, encryptionKey, iv, iv_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator, ak_true );
     return NULL;
    }
    if(( error =
         ak_mgm_context_encryption_update( &mgm, encryptionKey, authenticationKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect encryption of plain data" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator, ak_true );
     return NULL;
    }
  }

 /* в конце - вырабатываем имитовставку */
  if( authenticationKey != NULL ) {
    ak_error_set_value( ak_error_ok );
    result = ak_mgm_context_authentication_finalize( &mgm, authenticationKey, icode, icode_size );
    if(( error = ak_error_get_value()) != ak_error_ok ) {
      if( result != NULL ) result = ak_buffer_delete( result );
      ak_error_message( error, __func__, "incorrect finanlize of integrity code" );
    }
    ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator, ak_true );
  } else /* выше проверка того, что два ключа одновременно не равну NULL =>
                                                              один из двух ключей очистит контекст */
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator, ak_true );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных. Требования к передаваемым параметрам
    аналогичны требованиям, предъявляемым к параметрам функции ak_bckey_context_encrypt_mgm().


    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
           может принимать значение NULL;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции; может принимать значение NULL;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на расшифровываемые данные;
    @param out указатель на область памяти, куда будут помещены расшифрованные данные;
           данный указатель может совпадать с указателем in;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, в которой хранится значение имитовставки;
    @param icode_size размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;

    @return Функция возвращает истину (\ref ak_true), если значение имитовтсавки совпало с
            вычисленным в ходе выполнения функции значением; если значения не совпадают,
            или в ходе выполнения функции возникла ошибка, то возвращается ложь (\ref ak_false).
            При этом код ошибки может быть получен с
            помощью вызова функции ak_error_get_value().                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_context_decrypt_mgm( ak_bckey encryptionKey, ak_bckey authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  size_t bs = 0;
  struct mgm_ctx mgm; /* контекст структуры, в которой хранятся промежуточные данные */
  int error = ak_error_ok;
  ak_bool result = ak_false;

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL )) {
    ak_error_message( ak_error_null_pointer, __func__ ,
                               "using null pointers both to encryption and authentication keys" );
    return ak_false;
  }
  if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
    if( encryptionKey->bsize != authenticationKey->bsize ) {
      ak_error_message( ak_error_not_equal_data, __func__, "different block sizes for given keys");
      return ak_false;
    }
  }
   if( encryptionKey != NULL ) bs = encryptionKey->bsize;
     else bs = authenticationKey->bsize;

 /* проверяем размер входных данных */
  if(( error = ak_bckey_check_mgm_length( adata_size, size, bs )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect length of input data");
    return ak_false;
  }

 /* подготавливаем память */
  memset( &mgm, 0, sizeof( struct mgm_ctx ));

 /* в начале обрабатываем ассоциированные данные */
  if( authenticationKey != NULL ) {
    if(( error =
         ak_mgm_context_authentication_clean( &mgm, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator, ak_true );
     return ak_false;
    }
    if(( error =
         ak_mgm_context_authentication_update( &mgm, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect hashing of associated data" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator, ak_true );
     return ak_false;
    }
  }

 /* потом расшифровываем данные */
  if( encryptionKey != NULL ) {
    if(( error =
         ak_mgm_context_encryption_clean( &mgm, encryptionKey, iv, iv_size )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
      ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator, ak_true );
      return ak_false;
    }
    if(( error =
         ak_mgm_context_decryption_update( &mgm, encryptionKey, authenticationKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect encryption of plain data" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator, ak_true );
     return ak_false;
    }
  }

 /* в конце - вырабатываем имитовставку */
  if( authenticationKey != NULL ) {
    ak_uint8 icode2[16];
    memset( icode2, 0, 16 );

    ak_error_set_value( ak_error_ok );
    ak_mgm_context_authentication_finalize( &mgm, authenticationKey, icode2, icode_size );
    if(( error = ak_error_get_value()) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect finanlize of integrity code" );
     else {
      if( !ak_ptr_is_equal( icode, icode2, icode_size ))
        ak_error_message( ak_error_not_equal_data, __func__, "wrong value of integrity code" );
       else result = ak_true;
     }
    ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator, ak_true );

  } else { /* выше была проверка того, что два ключа одновременно не равну NULL =>
                                                              один из двух ключей очистит контекст */
         result = ak_true; /* мы ни чего не проверяли => все хорошо */
         ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator, ak_true );
        }

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                    реализация функций для выработки имитовставки (класс mgm)                    */
/* ----------------------------------------------------------------------------------------------- */
/*! @param gkey Контекст алгоритма выработки имитовставки.
    @param oid Идентификатор алгоритма выработки имитовставки в соответствии с ГОСТ Р 34.13-2015.
    @return В случае успешного завершения функция возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_create_oid( ak_mgm mctx, ak_oid oid )
{
  ak_oid bcoid = NULL;
  int error = ak_error_ok;

 /* выполняем проверку */
  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to mgm context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to mgm function oid" );
 /* проверяем, что OID от правильного алгоритма выработки имитовставки */
  if( oid->engine != mgm_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );

 /* получаем oid алгоритма блочного шифрования */
  if(( bcoid = ak_oid_context_find_by_name( oid->name+4 )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ ,
                                                   "incorrect searching of block cipher oid" );
 /* проверяем, что производящая функция определена */
  if( bcoid->func.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                         "using block cipher oid with undefined constructor" );
 /* инициализируем контекст ключа алгоритма блочного шифрования */
  if(( error =
           (( ak_function_bckey_create *)bcoid->func.create )( &mctx->bkey )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                                  "invalid creation of %s block cipher context", bcoid->name );
 /* доопределяем oid ключа */
  mctx->bkey.key.oid = oid;

 /* инициализируем структуру, хранящую внутренние состояния режима выработки имитовставки. */
  memset( &mctx->mctx, 0, sizeof( struct mgm_ctx ));
 /* инициализируем начальный вектор */
  if(( error = ak_buffer_create( &mctx->iv )) != ak_error_ok ) {
    ak_bckey_context_destroy( &mctx->bkey );
    return ak_error_message( error, __func__, "wrong creation a temporary buffer" );
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mctx Контекст алгоритма выработки имитовставки MGM на основе блочного шифра Магма.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_create_magma( ak_mgm mctx )
{ return ak_mgm_context_create_oid( mctx, ak_oid_context_find_by_name( "mgm-magma" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! @param mctx Контекст алгоритма выработки имитовставки MGM на основе блочного шифра Кузнечик.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_create_kuznechik( ak_mgm mctx )
{ return ak_mgm_context_create_oid( mctx, ak_oid_context_find_by_name( "mgm-kuznechik" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! @param mctx Контекст алгоритма выработки имитовставки MGM на основе блочного шифра Кузнечик.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_destroy( ak_mgm mctx )
{
  int error = ak_error_ok;

  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to mgm context" );
  if(( error = ak_buffer_destroy( &mctx->iv )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of internal buffer" );
  if(( error = ak_bckey_context_destroy( &mctx->bkey )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of block cipher key" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mctx Контекст алгоритма выработки имитовставки.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_mgm_context_delete( ak_pointer mctx )
{
  if( mctx != NULL ) {
      ak_mgm_context_destroy(( ak_mgm ) mctx );
      free( mctx );
     } else ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to mgm context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_set_iv( ak_mgm mctx, const ak_pointer ptr, const size_t size )
{
  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to mgm context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to initial vector" );
  if(( size == 0) || ( size > mctx->bkey.bsize )) return ak_error_message( ak_error_wrong_length,
                                        __func__, "using initial vector with unsupported length" );
  return ak_buffer_set_ptr( &mctx->iv, ptr, size, ak_true );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mctx Контекст алгоритма выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    @param size Размер данных, на которые указывает `ptr` (размер в байтах).
    Если величина `size` меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только `size` байт (остальные заполняются нулями). Если `size` больше, чем количество выделенной памяти
    под ключ, то копируются только младшие байты, в количестве `key.size` байт.

    @param cflag Флаг передачи владения укзателем `ptr`. Если `cflag` ложен (принимает значение `ak_false`),
    то физического копирования данных не происходит: внутренний буфер лишь указывает на размещенные
    в другом месте данные, но не владеет ими. Если `cflag` истиннен (принимает значение `ak_true`),
    то происходит выделение памяти и копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_set_key( ak_mgm mctx, const ak_pointer ptr,
                                                            const size_t size, const ak_bool cflag )
{
  int error = ak_error_ok;
  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to mgm context" );
  if(( error = ak_bckey_context_set_key( &mctx->bkey, ptr, size, cflag )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу случайное (псевдо-случайное) значение, размер которого определяется
    размером секретного ключа. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    @param mctx Контекст алгоритма выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    @param generator контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_set_key_random( ak_mgm mctx, ak_random generator )
{
  int error = ak_error_ok;
  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to mgm context" );
  if(( error = ak_bckey_context_set_key_random( &mctx->bkey, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи
    алгоритма PBKDF2, описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    Количество итераций алгоритма PBKDF2 определяется опцией библиотеки `pbkdf2_iteration_count`,
    значение которой может быть опредедено с помощью вызова функции ak_libakrypt_get_option().

    @param mctx Контекст алгоритма выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    @param pass Пароль, представленный в виде строки символов.
    @param pass_size Длина пароля в байтах.
    @param salt Случайная последовательность, представленная в виде строки символов.
    @param salt_size Длина случайной последовательности в байтах.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_set_key_from_password( ak_mgm mctx,
                                                const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;
  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to omac context" );
  if(( error = ak_bckey_context_set_key_from_password( &mctx->bkey,
                                          pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Контекст алгоритма выработки имитовставки.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_clean( ak_pointer ptr )
{
  int error = ak_error_ok;
  ak_mgm mctx = ( ak_mgm ) ptr;

  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to mgm context" );
  if( !((mctx->bkey.key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using mgm key with unassigned value" );
  if( mctx->iv.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using non initialized initial vector" );
  if(( error = ak_mgm_context_authentication_clean( &mctx->mctx, &mctx->bkey,
                                                 mctx->iv.data, mctx->iv.size )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect cleaning of mgm context" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Контекст алгоритма выработки имитовставки.
    @param data Указатель на обрабатываемые данные.
    @param size Длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемого алгоритма блочного шифрования.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_update( ak_pointer ptr, const ak_pointer data, const size_t size )
{
  int error = ak_error_ok;
  ak_mgm mctx = ( ak_mgm ) ptr;

  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using a null pointer to mgm key context" );
  if( data == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using a null pointer to plain data" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%mctx->bkey.bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
 /* проверяем наличие ключа */
  if(( error =
    ak_mgm_context_authentication_update( &mctx->mctx, &mctx->bkey, data, size )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect updating of mgm context" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Контекст алгоритма выработки имитовставки.
    @param data Блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных (блока блочного шифра: не более 7 для Магмы и 15 для Кузнечика).
    @param size Длина блока обрабатываемых данных
    @param out Указатель на область памяти, куда будет помещен результат; если out равен NULL,
           то создается новый буффер, в который помещается результат.
    @return Если out равен NULL, то возвращается указатель на созданный буффер. В противном случае
           возвращается NULL. В случае возникновения ошибки возывращается NULL. Код ошибки может
           быть получен c помощью вызова функции ak_error_get_value().                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_mgm_context_finalize( ak_pointer ptr, const ak_pointer data,
                                                               const size_t size, ak_pointer out )
{
  ak_buffer buf = NULL;
  int error = ak_error_ok;
  ak_mgm mctx = ( ak_mgm ) ptr;

  if( mctx == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                                       "using a null pointer to mgm key context" );
    return NULL;
  }
  if( data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to plain data" );
    return NULL;
  }
  if( size >= mctx->bkey.bsize ) { ak_error_message( ak_error_zero_length,
                                          __func__ , "using wrong length for authenticated data" );
    return NULL;
  }

 /* сжимаем оставшиеся данные */
  if( size > 0 )
    if(( error = ak_mgm_context_authentication_update( &mctx->mctx, &mctx->bkey,
                                                                  data, size )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect updating of mgm context" );
      return NULL;
    }

 buf = ak_mgm_context_authentication_finalize( &mctx->mctx, &mctx->bkey, out, mctx->bkey.bsize );
 if(( error = ak_error_get_value()) != ak_error_ok )
   ak_error_message( error, __func__, " incorrect finalizing of mgm context");
 return buf;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             реализация функций для тестирования                                 */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_test_mgm( void )
{
  char *str = NULL;
  ak_bool result = ak_false;
  int error = ak_error_ok, audit = ak_log_get_level();

 /* константные значения ключей из ГОСТ Р 34.13-2015 */
  ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 keyAnnexB[32] = {
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

 /* открытый текст, подлежащий зашифрованию (модификация ГОСТ Р 34.13-2015, приложение А.1) */
  ak_uint8 out[67];
  ak_uint8 plain[67] = {
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0xCC, 0xBB, 0xAA };

 /* несколько вариантов шифртекстов */
  ak_uint8 cipherOne[67] = {
     0xFC, 0x42, 0x9F, 0xE8, 0x3D, 0xA3, 0xB8, 0x55, 0x90, 0x6E, 0x95, 0x47, 0x81, 0x7B, 0x75, 0xA9,
     0x39, 0x6B, 0xC1, 0xAD, 0x9A, 0x06, 0xF7, 0xD3, 0x5B, 0xFD, 0xF9, 0x2B, 0x21, 0xD2, 0x75, 0x80,
     0x1C, 0x85, 0xF6, 0xA9, 0x0E, 0x5D, 0x6B, 0x93, 0x85, 0xBA, 0xA6, 0x15, 0x59, 0xB1, 0x7A, 0x49,
     0xEB, 0x6D, 0xC7, 0x95, 0x06, 0x42, 0x94, 0xAB, 0xD0, 0x83, 0xF8, 0xD3, 0xD4, 0x14, 0x0C, 0xC6,
     0x52, 0x75, 0x2C };

  ak_uint8 cipherThree[67] = {
     0x3B, 0xA0, 0x9E, 0x5F, 0x6C, 0x06, 0x95, 0xC7, 0xAE, 0x85, 0x91, 0x45, 0x42, 0x33, 0x11, 0x85,
     0x5D, 0x78, 0x2B, 0xBF, 0xD6, 0x00, 0x2E, 0x1F, 0x7D, 0x8E, 0x9C, 0xBB, 0xB8, 0x70, 0x04, 0x94,
     0x70, 0xDC, 0x7D, 0x1F, 0x73, 0xD3, 0x5D, 0x9A, 0x76, 0xA5, 0x6F, 0xCE, 0x0A, 0xCB, 0x27, 0xEC,
     0xD5, 0x75, 0xBB, 0x6A, 0x64, 0x5C, 0xF6, 0x70, 0x4E, 0xC3, 0xB5, 0xBC, 0xC3, 0x37, 0xAA, 0x47,
     0x9C, 0xBB, 0x03 };

 /* асссоциированные данные */
  ak_uint8 associated[41] = {
     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA };

 /* синхропосылки */
  ak_uint8 iv128[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
  ak_uint8 iv64[8] = {
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92 };

 /* значения для проверки вычисленного значения */
  ak_uint8 icode[16];
  ak_uint8 icodeOne[16] = {
    0x4C, 0xDB, 0xFC, 0x29, 0x0E, 0xBB, 0xE8, 0x46, 0x5C, 0x4F, 0xC3, 0x40, 0x6F, 0x65, 0x5D, 0xCF };
  ak_uint8 icodeTwo[16] = {
    0x57, 0x4E, 0x52, 0x01, 0xA8, 0x07, 0x26, 0x60, 0x66, 0xC6, 0xE9, 0x22, 0x57, 0x6B, 0x1B, 0x89 };
  ak_uint8 icodeThree[8] = { 0x10, 0xFD, 0x10, 0xAA, 0x69, 0x80, 0x92, 0xA7 };
  ak_uint8 icodeFour[8] = { 0xC5, 0x43, 0xDE, 0xF2, 0x4C, 0xB0, 0xC3, 0xF7 };

 /* ключи для проверки */
  struct bckey kuznechikKeyA, kuznechikKeyB, magmaKeyA, magmaKeyB;

 /* инициализация ключей */
 /* - 1 - */
  if(( error = ak_bckey_context_create_kuznechik( &kuznechikKeyA )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of first secret key");
    return ak_false;
  }
  if(( error = ak_bckey_context_set_key( &kuznechikKeyA, keyAnnexA, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_context_destroy( &kuznechikKeyA );
    ak_error_message( error, __func__, "incorrect assigning a first constant value to Kuznechik key");
    return ak_false;
  }
 /* - 2 - */
  if(( error = ak_bckey_context_create_kuznechik( &kuznechikKeyB )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of second secret key");
    ak_bckey_context_destroy( &kuznechikKeyA );
    return ak_false;
  }
  if(( error = ak_bckey_context_set_key( &kuznechikKeyB, keyAnnexB, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_context_destroy( &kuznechikKeyA );
    ak_bckey_context_destroy( &kuznechikKeyB );
    ak_error_message( error, __func__, "incorrect assigning a second constant value to Kuznechik key");
    return ak_false;
  }
 /* - 3 - */
  if(( error = ak_bckey_context_create_magma( &magmaKeyA )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of third secret key");
    ak_bckey_context_destroy( &kuznechikKeyA );
    ak_bckey_context_destroy( &kuznechikKeyB );
    return ak_false;
  }
  if(( error = ak_bckey_context_set_key( &magmaKeyA, keyAnnexA, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_context_destroy( &kuznechikKeyA );
    ak_bckey_context_destroy( &kuznechikKeyB );
    ak_bckey_context_destroy( &magmaKeyA );
    ak_error_message( error, __func__, "incorrect assigning a first constant value to Magma key");
    return ak_false;
  }
 /* - 4 - */
  if(( error = ak_bckey_context_create_magma( &magmaKeyB )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of fourth secret key");
    ak_bckey_context_destroy( &kuznechikKeyA );
    ak_bckey_context_destroy( &kuznechikKeyB );
    ak_bckey_context_destroy( &magmaKeyA );
    return ak_false;
  }
  if(( error = ak_bckey_context_set_key( &magmaKeyB, keyAnnexB, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_context_destroy( &kuznechikKeyA );
    ak_bckey_context_destroy( &kuznechikKeyB );
    ak_bckey_context_destroy( &magmaKeyA );
    ak_bckey_context_destroy( &magmaKeyB );
    ak_error_message( error, __func__, "incorrect assigning a first constant value to Magma key");
    return ak_false;
  }

 /* первый тест - шифрование и имитовставка, алгоритм Кузнечик, один ключ */
  memset( icode, 0, 16 );
  ak_bckey_context_encrypt_mgm( &kuznechikKeyA, &kuznechikKeyA, associated, sizeof( associated ),
                                    plain, out, sizeof( plain ), iv128, sizeof( iv128 ), icode, 16 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for first example");
    goto exit;
  }
  if( !ak_ptr_is_equal( icode, icodeOne, sizeof( icodeOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the integrity code for one Kuznechik key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( icode, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( icodeOne, 16, ak_true )); free( str );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, cipherOne, sizeof( cipherOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the encryption test for one Kuznechik key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( cipherOne, sizeof( out ), ak_true )); free( str );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if( !ak_bckey_context_decrypt_mgm( &kuznechikKeyA, &kuznechikKeyA,
            associated, sizeof( associated ), cipherOne, out, sizeof( cipherOne ),
                                                        iv128, sizeof( iv128 ), icodeOne, 16 )) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                    "checking the integrity code for one Kuznechik key is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the decryption test for one Kuznechik key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( plain, sizeof( out ), ak_true )); free( str );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
             "the 1st full encryption, decryption & integrity test with one Kuznechik key is Ok" );

 /* второй тест - шифрование и имитовставка, алгоритм Кузнечик, два ключа */
  memset( icode, 0, 16 );
  ak_bckey_context_encrypt_mgm( &kuznechikKeyA, &kuznechikKeyB, associated, sizeof( associated ),
                                  plain, out, sizeof( plain ), iv128, sizeof( iv128 ), icode, 16 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for second example");
    goto exit;
  }
  if( !ak_ptr_is_equal( icode, icodeTwo, sizeof( icodeTwo ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the integrity code for two Kuznechik keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( icode, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( icodeTwo, 16, ak_true )); free( str );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, cipherOne, sizeof( cipherOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                           "the encryption test for two Kuznechik keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( cipherOne, sizeof( out ), ak_true )); free( str );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if( !ak_bckey_context_decrypt_mgm( &kuznechikKeyA, &kuznechikKeyB,
            associated, sizeof( associated ), cipherOne, out, sizeof( cipherOne ),
                                                        iv128, sizeof( iv128 ), icodeTwo, 16 )) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                   "checking the integrity code for two Kuznechik keys is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                           "the decryption test for two Kuznechik keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( plain, sizeof( out ), ak_true )); free( str );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
            "the 2nd full encryption, decryption & integrity test with two Kuznechik keys is Ok" );

 /* третий тест - шифрование и имитовставка, алгоритм Магма, один ключ */
  memset( icode, 0, 16 );
  ak_bckey_context_encrypt_mgm( &magmaKeyB, &magmaKeyB, associated, sizeof( associated ),
                                     plain, out, sizeof( plain ), iv64, sizeof( iv64 ), icode, 8 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for third example");
    goto exit;
  }
  if( !ak_ptr_is_equal( icode, icodeThree, sizeof( icodeThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "the integrity code for one Magma key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( icode, 8, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( icodeThree, 8, ak_true )); free( str );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, cipherThree, sizeof( cipherThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the encryption test for one Magma key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( cipherThree,
                                                    sizeof( cipherThree ), ak_true )); free( str );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if( !ak_bckey_context_decrypt_mgm( &magmaKeyB, &magmaKeyB,
            associated, sizeof( associated ), cipherThree, out, sizeof( cipherThree ),
                                                          iv64, sizeof( iv64 ), icodeThree, 8 )) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                        "checking the integrity code for one Magma key is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the decryption test for one Magma key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( plain, sizeof( plain ), ak_true )); free( str );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                 "the 3rd full encryption, decryption & integrity test with one Magma key is Ok" );

 /* четвертый тест - шифрование и имитовставка, алгоритм Магма, два ключа */
  memset( icode, 0, 16 );
  ak_bckey_context_encrypt_mgm( &magmaKeyB, &magmaKeyA, associated, sizeof( associated ),
                                     plain, out, sizeof( plain ), iv64, sizeof( iv64 ), icode, 8 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for fourth example");
    goto exit;
  }
  if( !ak_ptr_is_equal( icode, icodeFour, sizeof( icodeFour ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the integrity code for two Magma keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( icode, 8, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( icodeFour, 8, ak_true )); free( str );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, cipherThree, sizeof( cipherThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                              "the encryption test for two Magma keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( cipherThree,
                                                    sizeof( cipherThree ), ak_true )); free( str );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if( !ak_bckey_context_decrypt_mgm( &magmaKeyB, &magmaKeyA,
            associated, sizeof( associated ), cipherThree, out, sizeof( cipherThree ),
                                                          iv64, sizeof( iv64 ), icodeFour, 8 )) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                       "checking the integrity code for two Magma keys is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                              "the decryption test for two Magma keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( plain, sizeof( plain ), ak_true )); free( str );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
               "the 4th full encryption, decryption & integrity test with two Magma keys is Ok" );

 /* только здесь все хорошо */
  result = ak_true;

 /* освобождение памяти */
  exit:
  ak_bckey_context_destroy( &magmaKeyB );
  ak_bckey_context_destroy( &magmaKeyA );
  ak_bckey_context_destroy( &kuznechikKeyB );
  ak_bckey_context_destroy( &kuznechikKeyA );

 return result;
}

/*! \todo Необходимо сделать цикл тестов со
    случайными имитовставками, вычисляемыми с помощью класса struct mac. */
/* ----------------------------------------------------------------------------------------------- */
/*!  \example test-internal-mgm01.c                                                                */
/*!  \example test-internal-mgm02.c                                                                */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mgm.c  */
/* ----------------------------------------------------------------------------------------------- */
