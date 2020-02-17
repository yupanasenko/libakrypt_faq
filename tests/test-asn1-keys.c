 #include <stdlib.h>
 #include <ak_asn1.h>
 #include <ak_asn1_keys.h>
 #include <ak_hash.h>
 #include <ak_tools.h>

 int main(void)
{
  ak_asn1 root = ak_asn1_context_new();
  struct bckey ekey, ikey;

 /* Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* получаем дерево и ключи */
  ak_asn1_context_add_derived_keys_from_password( root,
                         ak_oid_context_find_by_name( "kuznechik" ), &ekey, &ikey, "pass", 4 );
  ak_asn1_context_print( root, stdout );
  ak_skey_context_print_to_file( &ekey.key, stdout );
  ak_skey_context_print_to_file( &ikey.key, stdout );
  ak_bckey_context_destroy( &ekey );
  ak_bckey_context_destroy( &ikey );

 /* получаем ключи из дерева */
  if( ak_asn1_context_get_derived_keys_from_password( root, &ekey, &ikey ) != ak_error_ok ) {
    printf("get error\n");
    goto exlab;
  }

  ak_skey_context_print_to_file( &ekey.key, stdout );
  ak_skey_context_print_to_file( &ikey.key, stdout );
  ak_bckey_context_destroy( &ekey );
  ak_bckey_context_destroy( &ikey );

 exlab:
  ak_asn1_context_delete( root );
  return ak_libakrypt_destroy();
}
