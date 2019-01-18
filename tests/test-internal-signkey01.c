/* Пример, иллюстрирующий механизмы создания и удаления секретных ключей электронной подписи.
   Пример использует неэкспортируемые функции библиотеки.

   test-internal-signkey01.c
*/
 #include <stdio.h>
 #include <ak_sign.h>

 int main( void )
{
 ak_oid curveoid = NULL, algoid = NULL;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr ))
    return ak_libakrypt_destroy();

 /* перебираем все возможные кривые */
  curveoid = ak_oid_context_find_by_engine( identifier );
  while( curveoid != NULL ) {
   if( curveoid->mode == wcurve_params ) {
     printf("\n founded a %s curve (%s)\n", curveoid->name, curveoid->id );

     /* перебираем все возможные алгоритмы выработки подписи */
     algoid = ak_oid_context_find_by_engine( sign_function );
     while( algoid != NULL ) {
       if( algoid->mode == algorithm ) {
         int error = ak_error_ok;
         struct signkey secretKey;

         printf(" - %s (%s) [create: ", algoid->name, algoid->id );
         if(( error = ak_signkey_context_create_oid( &secretKey, algoid, curveoid )) == ak_error_ok ) {
           printf("Ok, destroy: ");

           /*

             ... здесь должны выполняться функции выработки и проверки электронной подписи ...

           */

           if( ak_signkey_context_destroy( &secretKey ) == ak_error_ok ) printf("Ok]\n");
            else  printf("Wrong]\n");
         } else  printf("Wrong]\n");
       }
       algoid = ak_oid_context_findnext_by_engine( algoid, sign_function );
     }
   }
   curveoid = ak_oid_context_findnext_by_engine( curveoid, identifier );
  }
  ak_error_set_value( ak_error_ok );
 return ak_libakrypt_destroy();
}
