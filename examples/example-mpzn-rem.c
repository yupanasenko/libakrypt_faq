 #include <ak_curves.h>
 #include <ak_oid.h>

/* основная тестирующая программа */
 int main( void )
{
 ak_libakrypt_create( ak_function_log_stderr );

 return ak_libakrypt_destroy();
}
