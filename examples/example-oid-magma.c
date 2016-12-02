 #include <libakrypt.h>

 int main( void )
{
 size_t idx = 0;
 /* в явном виде задаем таблицу замен для алгоритма ГОСТ 28147-89 */
 const ak_uint8 cipher_box_new[8][16] = {
       { 15, 12, 2, 10, 6, 4, 5, 0, 7, 9, 14, 13, 1, 11, 8, 3 },
       { 11, 6, 3, 4, 12, 15, 14, 2, 7, 13, 8, 0, 5, 10, 9, 1 },
       { 1, 12, 11, 0, 15, 14, 6, 5, 10, 13, 4, 8, 9, 3, 7, 2 },
       { 1, 5, 14, 12, 10, 7, 0, 13, 6, 2, 11, 4, 9, 3, 15, 8 },
       { 0, 12, 8, 9, 13, 2, 10, 11, 7, 3, 6, 5, 4, 14, 15, 1 },
       { 8, 0, 15, 3, 2, 5, 14, 11, 1, 10, 4, 7, 12, 9, 13, 6 },
       { 3, 0, 6, 15, 1, 14, 9, 2, 13, 8, 12, 4, 11, 10, 5, 7 },
       { 1, 10, 6, 8, 15, 11, 0, 4, 12, 3, 5, 9, 7, 13, 2, 14 }
};

 /* инициализируем библиотеку */
 if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();
 printf("libakrypt version %s: total count of OID's = %ld\n",
                                                 ak_libakrypt_version(), ak_oids_get_count());

 /* добавляем новую таблицу замен в список OID'ов */
  if( ak_oids_add_magma_tables( "id-my-magma-tables",
               "000.1.2.3.4.5.6.7.8.9.000", cipher_box_new ) != ak_error_ok ) {
     ak_error_message( ak_error_get_value(),
                            "wrong value of magma tables", "example-oid-magma");
 } else /* выводим все доступные OID */
    for( idx = 0; idx < ak_oids_get_count(); idx++ ) {
       ak_oid oid = ak_oids_get_oid( idx );
       printf(" %3d: [name = %s, oid = %s]\n", (int)idx+1,
                                  ak_oid_get_name( oid ), ak_oid_get_id( oid ));
    }
 return ak_libakrypt_destroy();
}
