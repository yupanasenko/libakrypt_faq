/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_random.с                                                                               */
/*  - содержит реализацию генераторов псевдо-случайных чисел                                       */
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
/*                                         реализация класса winrtl                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <windows.h>
 #include <wincrypt.h>
 #include <ak_random.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения контекста криптопровайдера. */
 typedef struct random_winrtl {
  /*! \brief контекст криптопровайдера */
  HCRYPTPROV handle;
} *ak_random_winrtl;

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_winrtl_random( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                           "use a data vector with wrong length" );

  if( !CryptGenRandom( (( ak_random_winrtl )rnd->data)->handle, (DWORD) size, ptr ))
    return ak_error_message( ak_error_undefined_value, __func__,
                                                    "wrong generation of pseudo random sequence" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static void ak_random_winrtl_free( ak_pointer ptr )
{
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "freeing a null pointer to data" );
    return;
  }
  if( !CryptReleaseContext( (( ak_random_winrtl )ptr )->handle, 0 )) {
    ak_error_message_fmt( ak_error_close_file,
            __func__ , "wrong closing a system crypto provider with error: %x", GetLastError( ));
  }
  free( ptr );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_random_context_create_winrtl( ak_random generator )
{
  HCRYPTPROV handle = 0;

  int error = ak_error_ok;
  if(( error = ak_random_context_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( generator->data = malloc( sizeof( struct random_winrtl ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
           "incorrect memory allocation for an internal variables of random generator" );

  /* теперь мы открываем криптопровайдер для доступа к генерации случайных значений
     в начале мы пытаемся создать новый ключ */
  if( !CryptAcquireContext( &handle, NULL, NULL,
                                         PROV_RSA_FULL, CRYPT_NEWKEYSET )) {
    /* здесь нам не удалось создать ключ, поэтому мы пытаемся его открыть */
    if( GetLastError() == NTE_EXISTS ) {
      if( !CryptAcquireContext( &handle, NULL, NULL,
                                         PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT )) {
        ak_error_message_fmt( error = ak_error_open_file, __func__,
                      "wrong open default key for system crypto provider with error: %x", GetLastError( ));
       ak_random_context_destroy( generator );
       return error;
      }
    } else {
       ak_error_message_fmt( error = ak_error_access_file, __func__,
                      "wrong creation of default key for system crypto provider with error: %x", GetLastError( ));
       ak_random_context_destroy( generator );
       return error;
     }
  }
  (( ak_random_winrtl )generator->data)->handle = handle;

  generator->oid = ak_oid_context_find_by_name("winrtl");
  generator->next = NULL;
  generator->randomize_ptr = NULL;
  generator->random = ak_random_winrtl_random;
  generator->free = ak_random_winrtl_free; /* эта функция должна закрыть открытый ранее криптопровайдер */

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_winrnd.c  */
/* ----------------------------------------------------------------------------------------------- */
