/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hmac.с                                                                                 */
/*  - содержит реализацию семейства ключевых алгоритмов хеширования HMAC.                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Выработка ключевой информации                                                           */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_derive_kdf256_to_buffer( ak_pointer master_key,
                                                  ak_uint8* label, const size_t label_size,
                         ak_uint8* seed, const size_t seed_size, ak_uint8 *out, const size_t size )
{
  int error = ak_error_ok;
  struct hmac ictx, *pctx = NULL;
  ak_uint8 cv[2] = { 0x01, 0x00 };
  ak_skey master = (ak_skey)master_key;

  if( master_key == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to master key" );
  if(( label == NULL ) && ( seed == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__,
                                                "using null pointer to both input data pointers" );
  if(( label_size == 0 ) && ( seed_size == 0 ))
    return ak_error_message( ak_error_null_pointer, __func__,
                                                "using zero length for both input data pointers" );
 /* проверяем, что мастер-ключ установлен */
  if( master->oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__,
                                   "using the master key which is not a cryptographic algorithm" );
  switch( master->oid->engine ) {
    case block_cipher:
    case hmac_function:
      break;
    default: return ak_error_message_fmt( ak_error_oid_engine, __func__,
                                              "using the master key with unsupported engine (%s)",
                                              ak_libakrypt_get_engine_name( master->oid->engine ));
  }

  if(( master->flags&key_flag_set_key ) == 0 )
    return ak_error_message( ak_error_key_value, __func__,
                                                     "using the master key with undefined value" );
  /* целостность ключа */
  if( master->check_icode( master ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                              __func__, "incorrect integrity code of master key" );

 /* если входящий контекст - hmac - используем его, в противном случае создаем новый */
  if( master->oid->engine == hmac_function ) {
    pctx = master_key;
  }
   else {
    /* создаем контект, который будет использован для генерации ключа */
     if(( error = ak_hmac_create_streebog256( &ictx )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect creation of intermac hmac context" );
    /* присваиваем указатель */
     pctx = &ictx;
    /* копируем значение исходного ключа */
     master->unmask( master );
     error = ak_hmac_set_key( pctx, master->key, master->key_size );
     master->set_mask( master );
     if( error != ak_error_ok ) {
       ak_error_message( error, __func__, "incorrect assigning a master key value" );
       goto labex;
     }
   }

 /* только теперь приступаем к выработке нового ключевого значения */
  ak_hmac_clean( pctx );
  ak_hmac_update( pctx, cv, 1 );
  if(( label != NULL ) && ( label_size != 0 )) ak_hmac_update( pctx, label, label_size );
  ak_hmac_update( pctx, cv+1, 1 );
  if(( seed != NULL ) && ( seed_size != 0 )) ak_hmac_update( pctx, seed, seed_size );
  error = ak_hmac_finalize( pctx, cv, 2, out, size );

  labex:
   if( pctx == &ictx ) ak_hmac_destroy( &ictx); /* удаляем свое, чужое не трогаем */
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации ключа используется алгоритм hmac256 с функцией хеширования Стрибог256.

    В процессе выполнения функция выделяет в памяти область  для новго ключа,
    инициализирует его и присваивает выработанное значение, а также устанавливает ресурс ключа.

    \param oid Идентификатор создаваемого ключа
    \param master_key Исходный ключ, используемый для генераци производного ключа
    \param label Используемая в алгоритме метка производного ключа
    \param label_size Длина метки (в октетах)
    \param seed Используемое в алгоритме инициализирующее значение
    \param seed_size Длина иициализирующего значения (в октетах)

    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
    возвращается \ref ak_error_ok (ноль).                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_new_derive_kdf256( ak_oid oid, ak_pointer master_key,
                ak_uint8* label, const size_t label_size, ak_uint8* seed, const size_t seed_size )
{
  ak_uint8 out[32]; /* размер 32 определяется используемым алгоритмом kdf256 */
  int error = ak_error_ok;
  ak_pointer handle = NULL;

 /* выполняем проверки */
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid context" );
    return NULL;
  }
  if( oid->func.first.set_key == NULL ) {
    ak_error_message_fmt( ak_error_undefined_function, __func__,
                                       "using oid (%s) with unsupported key assigning mechanism" );
    return NULL;
  }

 /* создаем производный ключ */
  if(( error = ak_skey_derive_kdf256_to_buffer( master_key,
                                 label, label_size, seed, seed_size, out, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect generation of derivative key" );
    goto labex;
  }

 /* погружаем данные в контекст */
  if(( handle = ak_oid_new_object( oid )) == NULL ) {
    ak_error_message( error = ak_error_get_value(), __func__,
                                                  "incorrect creation of new secret key context" );
    goto labex;
  }
  if(( error = oid->func.first.set_key( handle, out, 32 )) != ak_error_ok ) {
   ak_error_message( error, __func__, "incorrect assigning a derivative key value" );
   goto labex;
  }

 /* очищаем память */
  labex:
    if( error != ak_error_ok ) handle = ak_oid_delete_object( oid, handle );
    ak_ptr_wipe( out, sizeof( out ), &((ak_skey)master_key)->generator );

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                        ak_kdf.c */
/* ----------------------------------------------------------------------------------------------- */
