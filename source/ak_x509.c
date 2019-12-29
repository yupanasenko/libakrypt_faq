/* ----------------------------------------------------------------------------------------------- */
 #include <ak_asn1.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
 #include <ak_asn1.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает `SEQUENCE`, которая содержит два примитивных элемента -
    начало и окончание временного интервала.

   \param asn1 указатель на текущий уровень ASN.1 дерева.
   \param not_before начало временного интервала
   \param not_before окончание временного интервала
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_time_validity( ak_asn1 asn1, time_t not_before, time_t not_after )
{
  int error = ak_error_ok;
  ak_asn1 asn_validity = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if(( error = ak_asn1_context_create( asn_validity =
                                                 malloc( sizeof( struct asn1 )))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );

  if(( error = ak_asn1_context_add_utc_time( asn_validity, not_before )) != ak_error_ok ) {
    ak_asn1_context_delete( asn_validity );
    return ak_error_message( error, __func__, "incorrect adding \"not before\" time" );
  }
  if(( error = ak_asn1_context_add_utc_time( asn_validity, not_after )) != ak_error_ok ) {
    ak_asn1_context_delete( asn_validity );
    return ak_error_message( error, __func__, "incorrect adding \"not after\" time" );
  }

 return ak_asn1_context_add_asn1( asn1, TSEQUENCE, asn_validity );
}
