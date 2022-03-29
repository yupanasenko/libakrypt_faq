/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 - 2022 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_aead.c                                                                                 */
/*  - содержит функции, реализующие аутентифицированное шифрование                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup aead-doc Аутентифицированное шифрование данных
    \details Аутентифицированное шифрование (AEAD, Authenticated Ecncryption with Associated Data)
    представляет собой совокупность из одного или
    двух алгоритмов, позволяющих одновременно зашифровать данные и вычислить их имитовставку,
    обеспечивая тем самым конфиденциальность, целостность данных (имитозащиту),
    а также аутентификацию отправителя данных.

    В общем случае аутентифицированное шифрование может рассматриваться как отображение
    \f[
     AEAD:\quad \mathbb A \times \mathbb P \times \mathbb K_1 \times \mathbb K_2 \rightarrow
      \mathbb C \times \mathbb V_{m},
    \f]
    где
    - \f$ \mathbb A \subset \mathbb V_\infty\f$ -- пространство ассоциированных данных, т.е.
    данных, которые передаются в незашифрованном виде, но для которых должна
    обеспечиваться целостность.
    - \f$ \mathbb P \subset \mathbb V_\infty\f$ -- пространство открытых текстов,
    которые подлежат зашифрованию,
    - \f$ \mathbb C \subset \mathbb V_\infty\f$ -- пространство шифртекстов,
    - \f$ \mathbb K_1, \mathbb K_2 \f$ -- пространства ключей, используемых, соответственно, для
    шифрования и имитозащиты.

    Отметим, что в общем случае отображение, определяющее аутентифицированное шифрование,
    может зависеть от двух секретных ключей
     - ключа шифрования,
     - ключа имитозащиты.

    В ряде алгоритмов указанные ключи могут совпадать.

    Аутентифицированное шифрование может быть реализовано как одним алгоритмом, так и комбинацией
    двух независимых алгоритмов - шифрования и имитозащиты. Примером первого подхода служат:
    - режим `MGM`, регламентируемый  рекомендациями по стандартизации Р 1323565.1.026-2019,
      см. функции ak_aead_create_mgm_magma(), ak_aead_create_mgm_kuznechik().
    - режим `XTSMAC`, разработанный авторами библиотеки,
      см. функции ak_aead_create_xtsmac_magma(), ak_aead_create_xtsmac_kuznechik().

    Примером второго подхода служат комбинации:
    - шифрование в режиме счетчика `CTR` с вычислением имитовставки по алгоритму `CMAC`,
    регламентируемому стандартом ГОСТ Р 34.11-2012,
    - шифрование в режиме счетчика `CTR` с вычислением имитовставки по алгоритму `HMAC` и т.д.

    \note Алгоритм аутентифицированного шифрования может не принимать на вход зашифровываемые
    данные. В этом случае алгоритм должен действовать как обычный алгоритм имитозащиты.   */

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст aead алгоритма
    \param crf флаг необходимости создания ключа шифрования
    \param name идентификатор aead алгоритма
    \return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_keys( ak_aead ctx, bool_t crf, char *name )
{
   if(( ctx->oid = ak_oid_find_by_name( name )) == NULL )
     return ak_error_message_fmt( ak_error_oid_name, __func__, "invalid oid name \"%s\"", name );
   if( ctx->oid->mode != aead ) return ak_error_message_fmt( ak_error_oid_mode, __func__,
                                                             "oid mode must be an \"aead mode\"" );
  /* создаем ключи (значения не присваиваем) */
   if(( ctx->authenticationKey = ak_oid_new_second_object( ctx->oid )) == NULL )
     return ak_error_message( ak_error_get_value(), __func__,
                                            "incorrect memory allocation for authentication key" );
   ctx->encryptionKey = NULL;
   if( crf ) { /* по запросу пользователя создаем ключ шифрования */
     if(( ctx->encryptionKey = ak_oid_new_object( ctx->oid )) == NULL ) {
       ak_oid_delete_second_object( ctx->authenticationKey, ctx->oid );
       return ak_error_message( ak_error_get_value(), __func__,
                                                "incorrect memory allocation for encryption key" );
     }
   }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_oid( ak_aead ctx, bool_t crf, ak_oid oid )
{
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                     "using null pointer to oid" );
  if( oid->mode != aead ) return ak_error_message( ak_error_oid_mode, __func__,
                                                                  "using oid with non aead mode" );
  if( strncmp( oid->name[0], "mgm-magma", 9 ) == 0 )
    return ak_aead_create_mgm_magma( ctx, crf );
  if( strncmp( oid->name[0], "mgm-kuznechik", 13 ) == 0 )
    return ak_aead_create_mgm_kuznechik( ctx, crf );
  if( strncmp( oid->name[0], "xtsmac-magma", 12 ) == 0 )
    return ak_aead_create_xtsmac_magma( ctx, crf );
  if( strncmp( oid->name[0], "xtsmac-kuznechik", 16 ) == 0 )
    return ak_aead_create_xtsmac_kuznechik( ctx, crf );
  if( strncmp( oid->name[0], "ctr-cmac-magma", 14 ) == 0 )
    return ak_aead_create_ctr_cmac_magma( ctx, crf );
  if( strncmp( oid->name[0], "ctr-cmac-kuznechik", 18 ) == 0 )
    return ak_aead_create_ctr_cmac_kuznechik( ctx, crf );

 return ak_error_message( ak_error_wrong_oid, __func__, "using unsupported oid" );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_destroy( ak_aead ctx )
{
   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   if( ctx->oid == NULL ) return ak_error_message( ak_error_wrong_oid, __func__,
                                                         "destroying context with undefined oid" );
   if( ctx->authenticationKey != NULL )
     ak_oid_delete_second_object( ctx->oid, ctx->authenticationKey );
   if( ctx->encryptionKey != NULL ) ak_oid_delete_object( ctx->oid, ctx->encryptionKey );
   if( ctx->ictx != NULL ) free( ctx->ictx );

   ctx->oid = NULL;
   ctx->tag_size = 0;
   ctx->auth_clean = NULL;
   ctx->auth_update = NULL;
   ctx->auth_finalize = NULL;
   ctx->enc_clean = NULL;
   ctx->enc_update = NULL;
   ctx->dec_update = NULL;

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param iv синхропосылка
    \param iv_size размер синхропосылки (в октетах)
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_clean( ak_aead ctx, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->auth_clean == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to auth_clean function" );
  if( ctx->enc_clean == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to enc_clean function" );
  if(( error = ctx->auth_clean( ctx->ictx, ctx->authenticationKey, iv, iv_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of aead authentication context" );
  if(( error = ctx->enc_clean( ctx->ictx, ctx->encryptionKey, iv, iv_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of aead encryption context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param iv синхропосылка
    \param iv_size размер синхропосылки (в октетах)
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_auth_clean( ak_aead ctx, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->auth_clean == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to auth_clean function" );
  if(( error = ctx->auth_clean( ctx->ictx, ctx->authenticationKey, iv, iv_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of aead authentication context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param iv синхропосылка
    \param iv_size размер синхропосылки (в октетах)
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_encrypt_clean( ak_aead ctx, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->enc_clean == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to enc_clean function" );
  if(( error = ctx->enc_clean( ctx->ictx, ctx->encryptionKey, iv, iv_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of aead encryption context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param adata аутентфицируемые данные
    \param adata_size размер аутентифицируемых данных (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_auth_update( ak_aead ctx, const ak_pointer adata, const size_t adata_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->auth_update == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to auth_update function" );
  if(( error = ctx->auth_update( ctx->ictx,
                                     ctx->authenticationKey, adata, adata_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong updating of aead authentication context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param out область памяти, куда помещается код аутентификации (имитовставка)
    \param out_size размер код аутентификации (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_auth_finalize( ak_aead ctx, ak_pointer out, const size_t out_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->auth_finalize == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to auth_finalize function" );
  if(( error = ctx->auth_finalize( ctx->ictx,
                                         ctx->authenticationKey, out, out_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong finalizing of aead authentication context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param in область памяти, в которой хранятся открытые данные
    \param out область памяти, куда помещаются зашифрованые данные
    \param size размер данных (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_encrypt_update( ak_aead ctx, const ak_pointer in, ak_pointer out, const size_t size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->enc_update == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to enc_update function" );
  if(( error = ctx->enc_update( ctx->ictx, ctx->encryptionKey,
                                         ctx->authenticationKey, in, out, size )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect data encryption" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param in область памяти, в которой хранятся зашифровыванные данные
    \param out область памяти, куда помещаются расшифровываемые данные
    \param size размер данных (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_decrypt_update( ak_aead ctx, const ak_pointer in, ak_pointer out, const size_t size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->dec_update == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to enc_update function" );
  if(( error = ctx->dec_update( ctx->ictx, ctx->encryptionKey,
                                         ctx->authenticationKey, in, out, size )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect data decryption" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param key область памяти, в которой хранится значение ключа шифрования
    \param size размер ключа (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_set_encrypt_key( ak_aead ctx, const ak_pointer key, const size_t size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to encryption key" );
  if( ak_oid_check( ctx->oid ) != ak_true ) return ak_error_message( ak_error_wrong_oid, __func__,
                                                              "pointer is not object identifier" );
  return ctx->oid->func.first.set_key( ctx->encryptionKey, key, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param key область памяти, в которой хранится значение ключа аутентификации (имитозащиты)
    \param size размер ключа (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_set_auth_key( ak_aead ctx, const ak_pointer key, const size_t size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to authentication key" );
  if( ak_oid_check( ctx->oid ) != ak_true ) return ak_error_message( ak_error_wrong_oid, __func__,
                                                              "pointer is not object identifier" );
  return ctx->oid->func.second.set_key( ctx->authenticationKey, key, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param ekey область памяти, в которой хранится значение ключа шифрования
    \param esize размер ключа шифрования (в октетах).
    \param akey область памяти, в которой хранится значение ключа аутентификации (имитозащиты)
    \param asize размер ключа аутентификации (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_set_keys( ak_aead ctx, const ak_pointer ekey, const size_t esize,
                                                        const ak_pointer akey, const size_t asize )
{
  int error = ak_error_ok;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ak_oid_check( ctx->oid ) != ak_true ) return ak_error_message( ak_error_wrong_oid, __func__,
                                                              "pointer is not object identifier" );
  if( ctx->encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to encryption key" );
  if( ctx->authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to authentication key" );

  if(( error = ctx->oid->func.first.set_key( ctx->encryptionKey, ekey, esize )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect assigning of ecryption key value" );
  if(( error = ctx->oid->func.second.set_key( ctx->authenticationKey, akey, asize )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect assigning of ecryption key value" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_aead.c  */
/* ----------------------------------------------------------------------------------------------- */
