/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2016 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_xtsmac.c                                                                               */
/* ----------------------------------------------------------------------------------------------- */
/* реализация режима аутентифицирующего шифрования xtsmac                                          */
/*                                                                                                 */
/* в редакции статьи A.Yu.Nesterenko,
   Differential properties of authenticated encryption mode based on universal hash function (XTSMAC),
   2021 XVII International Symposium "Problems of Redundancy in Information and Control Systems".
   IEEE, 2021. P. 39-44, doi: https://doi.org/10.1109/REDUNDANCY52534.2021.9606446                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

#ifdef AK_HAVE_STDALIGN_H
 #include <stdalign.h>
#endif

/*!
    Detailed documentation for ``foo`` with some **reStructuredText** markup.

    Usage:

    .. code:: cpp

        foo ("bar"); // <-- OK
        foo (NULL);  // error, name can't be NULL

    In master conf.py you can add your own Sphinx extensions and then invoke custom directives:

    .. my-custom-directive::

        my-custom-directive-content
 */

 int foo( char *x )
{
 return 1;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, содержащая текущее состояние внутренних переменных режима
   аутентифицированного шифрования `xtsmac` */
 typedef struct xtsmac_ctx {
  /*! \brief Текущее значение имитовставки
      - 128 бит (16 байт) для Магмы, - 256 бит (32 байта) для Кузнечика */
   ak_uint64 sum[4];
  /*! \brief Вектор, используемый для маскирования шифруемой информации
      \details Для блочного шифра Магма вектор последовательно содержит значения:
        \f$$ \underbrace{\gamma_{2n} || \gamma_{2n+1}}_{128\:\text{бит}} || \underbrace{ k_0 || k_1 || k_2 || k_3 }_{256\:\text{бит}} \f$$, */
   union {
     ak_uint8 u8[64];
     ak_uint64 u64[8];
   } gamma;
  /*! \brief Размер обработанных зашифровываемых/расшифровываемых данных в битах */
   ssize_t pbitlen;
  /*! \brief Размер обработанных ассоциированных данных в битах */
   ssize_t abitlen;
  /*! \brief Флаги состояния контекста */
   ak_uint32 flags;
} *ak_xtsmac_ctx;


/* ----------------------------------------------------------------------------------------------- */
/* выработка следующего значения gamma_{n} = \alpha\gamma_{n-1} = \alpha^n\gamma_0 в поле F_{2^128}*/
/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_next_gamma64 { \
      t[0] = ctx->gamma.u64[0] >> 63; \
      t[1] = ctx->gamma.u64[1] >> 63; \
      ctx->gamma.u64[0] <<= 1; ctx->gamma.u64[1] <<= 1; ctx->gamma.u64[1] ^= t[0]; \
      if( t[1] ) ctx->gamma.u64[0] ^= 0x87; \
   }

 #define ak_xtsmac_update_sum64 { \
      register ak_uint64 v = 0; \
      t[0] ^= ctx->gamma.u64[2]; \
      v  = streebog_Areverse_expand_with_pi[0][tb[ 0]]; \
      v ^= streebog_Areverse_expand_with_pi[1][tb[ 1]]; \
      v ^= streebog_Areverse_expand_with_pi[2][tb[ 2]]; \
      v ^= streebog_Areverse_expand_with_pi[3][tb[ 3]]; \
      v ^= streebog_Areverse_expand_with_pi[4][tb[ 4]]; \
      v ^= streebog_Areverse_expand_with_pi[5][tb[ 5]]; \
      v ^= streebog_Areverse_expand_with_pi[6][tb[ 6]]; \
      v ^= streebog_Areverse_expand_with_pi[7][tb[ 7]]; \
      t[1] ^= v; \
      t[1] ^= ctx->gamma.u64[3]; \
      v  = streebog_Areverse_expand_with_pi[0][tb[ 8]]; \
      v ^= streebog_Areverse_expand_with_pi[1][tb[ 9]]; \
      v ^= streebog_Areverse_expand_with_pi[2][tb[10]]; \
      v ^= streebog_Areverse_expand_with_pi[3][tb[11]]; \
      v ^= streebog_Areverse_expand_with_pi[4][tb[12]]; \
      v ^= streebog_Areverse_expand_with_pi[5][tb[13]]; \
      v ^= streebog_Areverse_expand_with_pi[6][tb[14]]; \
      v ^= streebog_Areverse_expand_with_pi[7][tb[15]]; \
      t[0] ^= v; \
      t[0] ^= ctx->gamma.u64[4]; \
      v  = streebog_Areverse_expand_with_pi[0][tb[ 0]]; \
      v ^= streebog_Areverse_expand_with_pi[1][tb[ 1]]; \
      v ^= streebog_Areverse_expand_with_pi[2][tb[ 2]]; \
      v ^= streebog_Areverse_expand_with_pi[3][tb[ 3]]; \
      v ^= streebog_Areverse_expand_with_pi[4][tb[ 4]]; \
      v ^= streebog_Areverse_expand_with_pi[5][tb[ 5]]; \
      v ^= streebog_Areverse_expand_with_pi[6][tb[ 6]]; \
      v ^= streebog_Areverse_expand_with_pi[7][tb[ 7]]; \
      t[1] ^= v; \
      t[1] ^= ctx->gamma.u64[5]; \
      v  = streebog_Areverse_expand_with_pi[0][tb[ 8]]; \
      v ^= streebog_Areverse_expand_with_pi[1][tb[ 9]]; \
      v ^= streebog_Areverse_expand_with_pi[2][tb[10]]; \
      v ^= streebog_Areverse_expand_with_pi[3][tb[11]]; \
      v ^= streebog_Areverse_expand_with_pi[4][tb[12]]; \
      v ^= streebog_Areverse_expand_with_pi[5][tb[13]]; \
      v ^= streebog_Areverse_expand_with_pi[6][tb[14]]; \
      v ^= streebog_Areverse_expand_with_pi[7][tb[15]]; \
      t[0] ^= v; \
      ctx->sum[0] ^= t[0]; \
      ctx->sum[1] ^= t[1]; \
   }

 #define ak_xtsmac_authenticate_step64( inptr ) { \
     t[0] = *(inptr)^ctx->gamma.u64[0]; (inptr)++; \
     t[1] = *(inptr)^ctx->gamma.u64[1]; (inptr)++; \
     authenticationKey->encrypt( &authenticationKey->key, t, t ); \
     authenticationKey->encrypt( &authenticationKey->key, t +1, t +1 ); \
    /* обновляем промежуточное состояние имитовставки */ \
     ak_xtsmac_update_sum64; \
    /* изменяем значение маскирующей гаммы */ \
     ak_xtsmac_next_gamma64; \
   }

 #define ak_xtsmac_encrypt_step64( inptr, outptr ) { \
     t[0] = *(inptr)^ctx->gamma.u64[0]; (inptr)++; \
     t[1] = *(inptr)^ctx->gamma.u64[1]; (inptr)++; \
     encryptionKey->encrypt( &encryptionKey->key, t, t ); \
     encryptionKey->encrypt( &encryptionKey->key, t +1, t +1 ); \
     *(outptr) = t[0]^ctx->gamma.u64[0]; (outptr)++; \
     *(outptr) = t[1]^ctx->gamma.u64[1]; (outptr)++; \
    /* обновляем промежуточное состояние имитовставки */ \
     ak_xtsmac_update_sum64; \
    /* изменяем значение маскирующей гаммы */ \
     ak_xtsmac_next_gamma64; \
   }

 #define ak_xtsmac_decrypt_step64( inptr, outptr ) { \
     t[0] = temp[0] = *(inptr)^ctx->gamma.u64[0]; (inptr)++; \
     t[1] = temp[1] = *(inptr)^ctx->gamma.u64[1]; (inptr)++; \
    /* обновляем промежуточное состояние имитовставки */ \
     ak_xtsmac_update_sum64; \
    /* расшифровываем данные */ \
     encryptionKey->decrypt( &encryptionKey->key, temp, t ); \
     encryptionKey->decrypt( &encryptionKey->key, temp +1, t +1 ); \
     *(outptr) = t[0]^ctx->gamma.u64[0]; (outptr)++; \
     *(outptr) = t[1]^ctx->gamma.u64[1]; (outptr)++; \
    /* изменяем значение маскирующей гаммы */ \
     ak_xtsmac_next_gamma64; \
   }


/* ----------------------------------------------------------------------------------------------- */
/*                функции прямой реализации, без использования контекста aead                      */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует режим шифрования для блочного шифра с одновременным вычислением
    имитовставки. На вход функции подаются как данные, подлежащие зашифрованию,
    так и ассоциированные данные, которые не зашифровываются. При этом имитовставка вычисляется
    для всех переданных на вход функции данных.

    Режим `xtsmac` должен использовать для шифрования и выработки имитовставки два различных ключа -
    в этом случае длины блоков обрабатываемых данных для ключей должны совпадать (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если указатель на ключ имитозащиты равен `NULL`, то возбуждается ошибка.
    Если указатель на ключ шифрования равен `NULL`, то данные не зашифровываются, однако
    имитовставка вычисляется.

    \note Данный режим не позволяет обрабатывать сообщения, длина которых менее 16 октетов.

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на зашифровываеме данные;
    @param out указатель на зашифрованные данные;
    @param size размер зашифровываемых данных в байтах, должен быть не менее 16 октетов;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, куда будет помещено значение имитовставки;
           память должна быть выделена заранее;
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно
           превышать 16 октетов; если значение icode_size, то возвращается запрашиваемое количество
           старших байт результата вычислений.

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_xtsmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                   const size_t size, const ak_pointer iv, const size_t iv_size,
                                                       ak_pointer icode, const size_t icode_size )
{
  int error = ak_error_ok;
  struct xtsmac_ctx ctx; /* контекст структуры, в которой хранятся промежуточные данные */

  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных. Требования к передаваемым параметрам
    аналогичны требованиям, предъявляемым к параметрам функции ak_bckey_encrypt_xtsmac().

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на расшифровываемые данные;
    @param out указатель на область памяти, куда будут помещены расшифрованные данные;
           данный указатель может совпадать с указателем in;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, в которой хранится значение имитовставки;
    @param icode_size размер имитовставки в байтах; значение не должно превышать 16 октетов;

    @return Функция возвращает \ref ak_error_ok, если значение имитовставки совпало с
            вычисленным в ходе выполнения функции значением; если значения не совпадают,
            или в ходе выполнения функции возникла ошибка, то возвращается код ошибки.             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_xtsmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  int error = ak_error_ok;
  struct xtsmac_ctx ctx; /* контекст структуры, в которой хранятся промежуточные данные */

  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст aead алгоритма
    \param crf флаг необходимости создания ключа шифрования
    \return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_xtsmac_magma( ak_aead ctx, bool_t crf )
{
  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст aead алгоритма
    \param crf флаг необходимости создания ключа шифрования
    \return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_xtsmac_kuznechik( ak_aead ctx, bool_t crf )
{
  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_xtsmac.c  */
/* ----------------------------------------------------------------------------------------------- */
