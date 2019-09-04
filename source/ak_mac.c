/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mac.c                                                                                  */
/*  - содержит реализацию алгоритмов итерационного сжатия                                          */
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
 #include <ak_mac.h>

/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_create( ak_mac mctx, const size_t size, ak_pointer ictx,
                       ak_function_context_clean *clean, ak_function_context_update *update,
                                                          ak_function_context_finalize *finalize )
{
  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to mac context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                    "using zero length of input data block size" );
  if( size > ak_mac_context_max_buffer_size ) return ak_error_message( ak_error_wrong_length,
                                     __func__, "using very huge length of input data block size" );
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to internal context" );
  memset( mctx->data, 0, sizeof( mctx->data ));
  mctx->length = 0;
  mctx->bsize = size;
  mctx->ctx = ictx;
  mctx->clean = clean;
  mctx->update = update;
  mctx->finalize = finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_destroy( ak_mac mctx )
{
  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to mac context" );
  memset( mctx->data, 0, sizeof( mctx->data ));
  mctx->length = 0;
  mctx->bsize = 0;
  mctx->ctx = NULL;
  mctx->clean = NULL;
  mctx->update = NULL;
  mctx->finalize = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mac.c  */
/* ----------------------------------------------------------------------------------------------- */
