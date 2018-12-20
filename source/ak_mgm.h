/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mac.h                                                                                  */
/*  - содержит описания функций, реализующих аутентифицированное шифрование
      и различные режимы его применения.                                                           */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_MGM_H__
#define __AK_MGM_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_gf2n.h>
 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, содержащая текущее состояние внутренних переменных режима
   аутентифицированного шифрования. */
 typedef struct __attribute__((aligned(16))) mgm_ctx {
  /*! \brief Текущее значение имитовставки. */
   ak_uint128 sum;
  /*! \brief Счетчик, значения которого используются при шифровании информации. */
   ak_uint128 ycount;
  /*! \brief Счетчик, значения которого используются при выработке имитовставки. */
   ak_uint128 zcount;
  /*! \brief Размер обработанных зашифровываемых/расшифровываемых данных в битах. */
   ssize_t pbitlen;
  /*! \brief Размер обработанных дополнительных данных в битах. */
   ssize_t abitlen;
  /*! \brief Флаги состояния контекста. */
   ak_uint32 flags;
} *ak_mgm_ctx;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ алгоритма выработки имитовставки, входящего в режим
   аутентифицированного шифрования. */
 typedef struct mgm {
 /*! \brief Контекст секретного ключа аутентификации. */
  struct bckey bkey;
 /*! \brief Текущее состояние внутренних переменных алгоритма аутентифицированного шифрования. */
  struct mgm_ctx mctx;
} *ak_mgm;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация начального значения внутреннего состояния алгоритма MGM перед
    обработкой дополнительных данных. */
 int ak_mgm_context_authentication_clean( ak_mgm_ctx , ak_bckey , const ak_pointer , const size_t );
/*! \brief Изменение значения внутреннего состояния алгоритма MGM при обработке дополнительных данных. */
 int ak_mgm_context_authentication_update( ak_mgm_ctx, ak_bckey , const ak_pointer , const size_t );
/*! \brief Завершение действий и вычисление имитовставки. */
 ak_buffer ak_mgm_context_authentication_finalize( ak_mgm_ctx ,
                                                              ak_bckey , ak_pointer, const size_t );
/*! \brief Инициализация начального значения счетчика для шифрования. */
 int ak_mgm_context_encryption_clean( ak_mgm_ctx , ak_bckey , const ak_pointer , const size_t );
/*! \brief Зашифрование данных и обновление внутреннего состояния счетчика для шифрования. */
 int ak_mgm_context_encryption_update( ak_mgm_ctx , ak_bckey ,
                                          ak_bckey , const ak_pointer , ak_pointer , const size_t );
/*! \brief Расшифрование данных и обновление внутреннего состояния счетчика для шифрования. */
 int ak_mgm_context_decryption_update( ak_mgm_ctx , ak_bckey ,
                                          ak_bckey , const ak_pointer , ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Зашифрование данных в режиме MGM с одновременной выработкой имитовставки. */
 ak_buffer ak_bckey_context_encrypt_mgm( ak_bckey , ak_bckey , const ak_pointer , const size_t ,
                   const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                         ak_pointer , const size_t );

/*! \brief Расшифрование данных в режиме MGM с одновременной проверкой имитовставки. */
 ak_bool ak_bckey_context_decrypt_mgm( ak_bckey , ak_bckey , const ak_pointer , const size_t ,
                   const ak_pointer , ak_pointer , const size_t , const ak_pointer , const size_t ,
                                                                          ak_pointer, const size_t );
/*! \brief Тестирование корректной работы режима блочного шифрования с одновременной
    выработкой имитовставки. */
 ak_bool ak_bckey_test_mgm( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mgm.h  */
/* ----------------------------------------------------------------------------------------------- */
