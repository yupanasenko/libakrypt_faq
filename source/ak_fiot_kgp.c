/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_fiot_kgp.с                                                                             */
/*  - содержит функции, используемые при реализации протокола выработки общих ключей               */
/*     (Key Generation Protocol)                                                                    */
/* ----------------------------------------------------------------------------------------------- */
//#ifdef LIBAKRYPT_HAVE_STDLIB_H
// #include <stdlib.h>
//#else
// #error Library cannot be compiled without stdlib.h header
//#endif
//#ifdef LIBAKRYPT_HAVE_STRING_H
// #include <string.h>
//#else
// #error Library cannot be compiled without string.h header
//#endif
//#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
// /* заголовок нужен для реализации функции send */
// #include <sys/socket.h>
//#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_fiot.h>

/* ----------------------------------------------------------------------------------------------- */
/* заглушка */
 int ak_fiot_context_keys_generation_protocol( ak_fiot fctx )
{
 /* запуск функции проверки состояния контекста:  */

  (void) fctx;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  ak_fiot_kgp.c  */
/* ----------------------------------------------------------------------------------------------- */
