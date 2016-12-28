#include <stdio.h>
#include <libakrypt.h>
#include <ak_curves.h>
#include <ak_parameters.h>
#include <ak_oid.h>
#include <ak_curves.h>

 int main( void )
{
 ak_bool result;
 size_t idx = 0;

 /* инициализируем библиотеку с функцией аудита в стандартный поток вывода ошибок */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

  for( idx = 0; idx < ak_oids_get_count(); idx++ ) {
     ak_oid oid = ak_oids_get_oid( idx );
     if( ak_oid_get_mode( oid ) == wcurve_params ) {
       const ak_wcurve_paramset ecp = (const ak_wcurve_paramset) oid->data;
       ak_wcurve ec = ak_wcurve_new(ecp);
       ak_wpoint wp = ak_wpoint_new(ecp);

       printf(" curve: %s [%s]", ak_oid_get_name(oid), ak_oid_get_id( oid ));
       if( result = ak_wcurve_is_ok( ec )) printf(" is Ok\n"); else printf(" is wrong\n");

       if( result ) {
         if( ak_wpoint_is_ok( wp, ec )) printf(" point is Ok\n"); else printf(" point is wrong\n");
         printf("  px = %s\n", ecp->cpx );
         printf("  py = %s\n", ecp->cpy );
         if( ak_wpoint_check_order( wp, ec )) printf(" order is Ok\n"); else printf(" order is wrong\n");
       }
       wp = ak_wpoint_delete( wp );
       ec = ak_wcurve_delete( ec );
     }
  }

  return ak_libakrypt_destroy();
}

