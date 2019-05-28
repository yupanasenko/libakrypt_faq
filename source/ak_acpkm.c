/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_acpkm.h                                                                                */
/*  - содержит реализацию криптографических алгоритмов семейства ACPKM из Р 1323565.1.017—2018     */
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
/*! \details Функция вычисляет новое значение секретного ключа в соответствии с соотношениями
    из раздела 4.1, см. Р 1323565.1.017—2018.
    После выработки новое значение помещается вместо старого.
    Одновременно, изменяется ресурс нового ключа: его тип принимает значение - \ref key_using_resource,
    а счетчик принимает значение, определяемое одной из опций

     - `ackpm_section_magma_block_count`,
     - `ackpm_section_kuznechik_block_count`.

    @param bkey Контекст ключа алгоритма блочного шифрования, для которого вычисляется
    новое значение. Контекст должен быть инициализирован и содержать ключевое значение.
    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_next_acpkm_key( ak_bckey bkey )
{
  ssize_t counter = 0;
  int error = ak_error_ok;
  ak_uint8 new_key[32], acpkm[32] = {
     0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
     0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80 };

 /* проверки */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to block cipher key" );
  if( bkey->key.key.size != 32 ) return ak_error_message_fmt( ak_error_wrong_length, __func__,
                                 "using block cipher key with unexpected length %u", bkey->bsize );
 /* целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* выработка нового значения */
   switch( bkey->bsize ) {
      case  8: /* шифр с длиной блока 64 бита */
         bkey->encrypt( &bkey->key, acpkm, new_key );
         bkey->encrypt( &bkey->key, acpkm +8, new_key +8 );
         bkey->encrypt( &bkey->key, acpkm +16, new_key +16 );
         bkey->encrypt( &bkey->key, acpkm +24, new_key +24 );
         counter = ak_libakrypt_get_option( "acpkm_section_magma_block_count" );
         break;
      case 16: /* шифр с длиной блока 128 бит */
         bkey->encrypt( &bkey->key, acpkm, new_key );
         bkey->encrypt( &bkey->key, acpkm +16, new_key +16 );
         counter = ak_libakrypt_get_option( "acpkm_section_kuznechik_block_count" );
         break;
      default: return ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
   }

 /* присваиваем ключу значение */
  if(( error = ak_bckey_context_set_key( bkey, new_key, bkey->key.key.size, ak_true )) != ak_error_ok )
    ak_error_message( error, __func__ , "can't replace key by new using acpkm" );
   else {
           bkey->key.resource.type = key_using_resource;
           bkey->key.resource.value.counter = counter;
        }
  ak_ptr_wipe( new_key, sizeof( new_key ), &bkey->key.generator, ak_true );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  #define acpkm_block64 {\
              nkey.encrypt( &nkey.key, ctr, yaout );\
              ctr[0] += 1;\
              ((ak_uint64 *) outptr)[0] = yaout[0] ^ ((ak_uint64 *) inptr)[0];\
              outptr++; inptr++;\
           }

  #define acpkm_block128 {\
              nkey.encrypt( &nkey.key, ctr, yaout );\
              if(( ctr[0] += 1 ) == 0 ) ctr[1]++;\
              ((ak_uint64 *) outptr)[0] = yaout[0] ^ ((ak_uint64 *) inptr)[0];\
              ((ak_uint64 *) outptr)[1] = yaout[1] ^ ((ak_uint64 *) inptr)[1];\
              outptr += 2; inptr += 2;\
           }

#else
  #define acpkm_block64 {\
              nkey.encrypt( &nkey.key, ctr, yaout );\
              ctr[0] = bswap_64( ctr[0] ); ctr[0] += 1; ctr[0] = bswap_64( ctr[0] );\
              ((ak_uint64 *) outptr)[0] = yaout[0] ^ ((ak_uint64 *) inptr)[0];\
              outptr++; inptr++;\
           }

  #define acpkm_block128 {\
              nkey.encrypt( &nkey.key, ctr, yaout );\
              ctr[0] = bswap_64( ctr[0] ); ctr[0] += 1; ctr[0] = bswap_64( ctr[0] );\
              if( ctr[0] == 0 ) { \
                ctr[1] = bswap_64( ctr[0] ); ctr[1] += 1; ctr[1] = bswap_64( ctr[0] );\
              }\
              ((ak_uint64 *) outptr)[0] = yaout[0] ^ ((ak_uint64 *) inptr)[0];\
              ((ak_uint64 *) outptr)[1] = yaout[1] ^ ((ak_uint64 *) inptr)[1];\
              outptr += 2; inptr += 2;\
           }
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! В режиме ACPKM для шифрования используется операция гаммирования - операция сложения открытого
    (зашифровываемого) текста с гаммой, вырабатываемой шифром, по модулю два. Поэтому, для зашифрования
    и расшифрования информациии используется одна и та же функция.

    В процессе шифрования исходные данные разбиваются на секции фиксированной длины, после чего
    каждая секция шифруется на своем ключе. Длина секции является параметром алгоритма и
    не должна превосходить величины, определяемой одной из следующих технических характеристик
    (опций)

     - `ackpm_section_magma_block_count`,
     - `ackpm_section_kuznechik_block_count`.

    Значение синхропосылки `iv` копируется и, в ходе выполнения функции, не изменяется.
    Повторный вызов функции ak_bckey_context_ctr_acpkm(),
    как в случае функции ak_bckey_context_ctr(), не допускается.

    @param bkey Контекст ключа алгоритма блочного шифрования,
    используемый для шифрования и порождения цепочки производных ключей.
    @param in Указатель на область памяти, где хранятся входные (зашифровываемые/расшифровываемые) данные
    @param out Указатель на область памяти, куда помещаются выходные (расшифровываемые/зашифровываемые) данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах). Длина зашифровываемых данных может
    принимать любое значение, не превосходящее \f$ 2^{\frac{8n}{2}-1}\f$, где \f$ n \f$
    длина блока алгоритма шифрования (8 или 16 байт).

    @param section_size Размер одной секции в байтах. Данная величина должна быть кратна длине блока
    используемого алгоритма шифрования.

    @param iv имитовставка
    @param iv_size длина имитовставки (в байтах)

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_ctr_acpkm( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                 size_t section_size, ak_pointer iv, size_t iv_size)
{
  struct bckey nkey;
  int error = ak_error_ok;
  ssize_t j = 0, sections = 0, tail = 0, seclen = 0, maxseclen = 0;
  ak_uint64 yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out, ctr[2] = { 0, 0 };

 /* выполняем проверку размера входных данных */
  if( section_size%bkey->bsize != 0 ) return ak_error_message( ak_error_wrong_block_cipher_length,
                               __func__ , "the length of section is not divided by block length" );
 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                  "incorrect integrity code of secret key value" );
 /* проверяем размер синхропосылки */
  if( iv_size < ( bkey->bsize >> 1 ))
    return ak_error_message( ak_error_wrong_block_cipher_length,
                                   __func__ , "the length of initialization vector is incorrect" );

 /* получаем максимально возможную длину секции,
             а также устанавливаем синхропосылку */
  switch( bkey->bsize ) {
    case 8:
       maxseclen = ak_libakrypt_get_option( "acpkm_section_magma_block_count" );
       #ifdef LIBAKRYPT_LITTLE_ENDIAN
         ctr[0] = ((ak_uint64 *)iv)[0] << 32;
       #else
         ctr[0] = ((ak_uint32 *)iv)[0];
       #endif
      break;
    case 16:
       maxseclen = ak_libakrypt_get_option( "acpkm_section_kuznechik_block_count" );
       ctr[1] = ((ak_uint64 *) iv)[0];
      break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
  }
 /* проверяем, что пользователь определил длину секции не очень большим значением */
  seclen = ( ssize_t )( section_size/bkey->bsize );
  if( seclen > maxseclen ) return ak_error_message( ak_error_wrong_length, __func__,
                                                                 "section has very large length" );
 /* проверяем ресурс ключа перед использованием */
  if( bkey->key.resource.type != key_using_resource ) { /* мы пришли сюда в первый раз */
    bkey->key.resource.type = key_using_resource;
    bkey->key.resource.value.counter = maxseclen;
  } else {
      if( bkey->key.resource.value.counter < 1 )
        return ak_error_message( ak_error_low_key_resource,
                                         __func__ , "low key using resource of block cipher key" );
       else bkey->key.resource.value.counter--;
     }

 /* теперь размножаем исходный ключ */
  if(( error = ak_bckey_context_create_and_set_bckey( &nkey, bkey )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect key duplication" );
 /* и меняем ресурс для производного ключа */
  nkey.key.resource.value.counter = maxseclen;

 /* дальнейшие киптографические действия применяются к новому экземляру ключа,
    для старого ключа лишь меняется значение ресурса */

 /* теперь можно приступать к шифрованию */
  sections = ( ssize_t )( size/section_size );
  tail = ( ssize_t )( size - ( size_t )( sections*seclen )*nkey.bsize );
  if( sections > 0 ) {
    do{
       switch( nkey.bsize ) { /* обрабатываем одну секцию */
         case 8: for( j = 0; j < seclen; j++ ) acpkm_block64; break;
         case 16: for( j = 0; j < seclen; j++ ) acpkm_block128; break;
         default: ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
       }
      /* вычисляем следующий ключ */
       if(( error = ak_bckey_context_next_acpkm_key( &nkey )) != ak_error_ok ) {
         ak_error_message_fmt( error, __func__, "incorrect key generation after %u sections",
                                                                         (unsigned int) sections );
         goto labex;
       }
    } while( --sections > 0 );
  } /* конец обработки случая, когда sections > 0 */

  if( tail ) { /* теперь обрабатываем фрагмент данных, не кратный длине секции */
    if(( seclen = tail/(ssize_t)( nkey.bsize )) > 0 ) {
       switch( nkey.bsize ) { /* обрабатываем данные, кратные длине блока */
         case 8: for( j = 0; j < seclen; j++ ) acpkm_block64; break;
         case 16: for( j = 0; j < seclen; j++ ) acpkm_block128; break;
         default: ak_error_message( ak_error_wrong_block_cipher,
                                            __func__ , "incorrect block size of block cipher key" );
       }
    }
  /* остался последний фрагмент, длина которого меньше длины блока
                      в качестве гаммы мы используем старшие байты */
    if(( tail -= seclen*(ssize_t)( nkey.bsize )) > 0 ) {
      nkey.encrypt( &nkey.key, ctr, yaout );
      for( j = 0; j < tail; j++ ) ((ak_uint8 *) outptr)[j] =
                         ((ak_uint8 *)yaout)[(ssize_t)nkey.bsize-tail+j] ^ ((ak_uint8 *) inptr)[j];
    }
  }

  labex: ak_bckey_context_destroy( &nkey );
 return error;
}

#if 0
 /* ----------------------------------------------------------------------------------------------- */
 /*! @param bkey Контекст ключа алгоритма блочного шифрования.
     @return В случае возникновения ошибки функция возвращает ее код, в противном случае
     возвращается ak_error_ok (ноль)                                                                */
  /* ----------------------------------------------------------------------------------------------- */
  static int ak_acpkm( ak_bckey bkey )
 {
   ak_uint8 acpkm_D[32] = {
      0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
      0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80
 };

   size_t i;
   ak_uint64 *new_key = bkey->key.key.alloc(bkey->key.key.size);
   ak_uint64 *new_key_for_set = new_key;
   ak_uint64 *D = (ak_uint64 *) acpkm_D;

   bkey->key.unmask(&bkey->key);
   for( i = 0; i < bkey->key.key.size; i+=bkey->bsize ) {
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
 static int ak_get_next_key( ak_bckey bkey, ak_uint64 ctr[2], ak_uint64 ki[4], ak_uint64 ki1[2], ak_uint64 *T, ak_uint64 Ts)
{
  ak_uint64 i;
  ak_uint64 blocks = 1 + (ak_uint64) bkey->key.key.size / bkey->bsize;

  for( i=0; i < blocks; ++i) {
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
#endif

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_bckey_test_acpkm( void )
{
  struct bckey key;
  int error = ak_error_ok, audit = ak_log_get_level();
  ak_uint8 skey[32] = {
      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
  };
  ak_uint8 iv1[8] = { 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12 };
  ak_uint8 iv2[4] = { 0x78, 0x56, 0x34, 0x12 };

  ak_uint8 out[112], in1[112] = {
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
      0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
      0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
      0x33, 0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
      0x44, 0x33, 0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55
  };
  ak_uint8 out1[112] = {
      0xb8, 0xa1, 0xbd, 0x40, 0xa2, 0x5f, 0x7b, 0xd5, 0xdb, 0xd1, 0x0e, 0xc1, 0xbe, 0xd8, 0x95, 0xf1,
      0xe4, 0xde, 0x45, 0x3c, 0xb3, 0xe4, 0x3c, 0xf3, 0x5d, 0x3e, 0xa1, 0xf6, 0x33, 0xe7, 0xee, 0x85,
      0x00, 0xe8, 0x85, 0x5e, 0x27, 0x06, 0x17, 0x00, 0x55, 0x4c, 0x6f, 0x64, 0x8f, 0xeb, 0xce, 0x4b,
      0x46, 0x50, 0x80, 0xd0, 0xaf, 0x34, 0x48, 0x3e, 0x39, 0x94, 0xd0, 0x68, 0xf5, 0x4d, 0x7c, 0x58,
      0x6e, 0x89, 0x8a, 0x6b, 0x31, 0x6c, 0xfc, 0x1c, 0xe1, 0xec, 0xae, 0x86, 0x76, 0xf5, 0x30, 0xcf,
      0x3e, 0x16, 0x23, 0x34, 0x74, 0x3b, 0x4f, 0x0c, 0x46, 0x36, 0x36, 0x81, 0xec, 0x07, 0xfd, 0xdf,
      0x5d, 0xde, 0xd6, 0xfb, 0xe7, 0x21, 0xd2, 0x69, 0xd4, 0xc8, 0xfa, 0x82, 0xc2, 0xa9, 0x09, 0x64
  };
  ak_uint8 in2[56] = {
      0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, /* по сравнению с текстом рекомендаций открытый */
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* текст выведен в блоки по 8 байт и развернут  */
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, /* в обратном порядке, по аналогии со способом, */
      0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, /* использованом в стандарте на блочные шифры   */
      0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99,
      0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22
  };
  ak_uint8 out2[56] = {
      0xab, 0x4c, 0x1e, 0xeb, 0xee, 0x1d, 0xb8, 0x2a,
      0xea, 0x94, 0x6b, 0xbd, 0xc4, 0x04, 0xe1, 0x68,
      0x6b, 0x5b, 0x2e, 0x6c, 0xaf, 0x67, 0x2c, 0xc7,
      0x2e, 0xb3, 0xf1, 0x70, 0x17, 0xb6, 0xaf, 0x0e,
      0x82, 0x13, 0xed, 0x9e, 0x14, 0x71, 0xae, 0xa1,
      0x6f, 0xec, 0x72, 0x06, 0x18, 0x67, 0xd4, 0xab,
      0xc1, 0x72, 0xca, 0x3f, 0x5b, 0xf1, 0xa2, 0x84
  };

 /* 1. Выполняем тест для алгоритма Магма */
  if(( error = ak_bckey_context_create_magma( &key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of magma secret key" );
    return ak_false;
  }
  if(( error = ak_bckey_context_set_key( &key, skey, sizeof( skey ), ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a key value" ); goto ex1; }

  if(( error = ak_bckey_context_ctr_acpkm( &key, in2, out, sizeof( in2 ),
                                                       16, iv2, sizeof( iv2 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption of plain text" ); goto ex1; }

  if( memcmp( out, out2, sizeof( in2 )) != 0 ) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
                "incorrect data comparizon after acpkm encryption with Magma cipher" ); goto ex1; }
 /* расшифровываем */
  if(( error = ak_bckey_context_ctr_acpkm( &key, out2, out, sizeof( in2 ),
                                                       16, iv2, sizeof( iv2 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption of plain text" ); goto ex1; }

  if( memcmp( out, in2, sizeof( in2 )) != 0 ) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
                "incorrect data comparizon after acpkm decryption with Magma cipher" ); goto ex1; }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                    "encryption/decryption test for Magma is Ok" );
  ex1: ak_bckey_context_destroy( &key );
  if( error != ak_error_ok ) {
    ak_error_message( ak_error_ok, __func__ , "acpkm mode test for Magma is wrong" );
    return ak_false;
  }

 /* 2. Выполняем тест для алгоритма Кузнечик */
  if(( error = ak_bckey_context_create_kuznechik( &key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of kuznechik secret key" );
    return ak_false;
  }
  if(( error = ak_bckey_context_set_key( &key, skey, sizeof( skey ), ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a key value" ); goto ex2; }

  if(( error = ak_bckey_context_ctr_acpkm( &key, in1, out, sizeof( in1 ),
                                                       32, iv1, sizeof( iv1 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption of plain text" ); goto ex2; }

  if( memcmp( out, out1, sizeof( in1 )) != 0 ) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
            "incorrect data comparizon after acpkm encryption with Kuznechik cipher" ); goto ex2; }
 /* расшифровываем */
  if(( error = ak_bckey_context_ctr_acpkm( &key, out1, out, sizeof( out1 ),
                                                        32, iv1, sizeof( iv1 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption of plain text" ); goto ex2; }

  if( memcmp( out, in1, sizeof( in1 )) != 0 ) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
            "incorrect data comparizon after acpkm decryption with Kuznechik cipher" ); goto ex2; }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                "encryption/decryption test for Kuznechik is Ok" );
  ex2: ak_bckey_context_destroy( &key );
  if( error != ak_error_ok ) {
    ak_error_message( ak_error_ok, __func__ , "acpkm mode test for Kuznechik is wrong" );
    return ak_false;
  }

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_acpkm.c */
/* ----------------------------------------------------------------------------------------------- */
