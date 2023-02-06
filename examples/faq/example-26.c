#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

int main( void )
{
    if( ak_libakrypt_create( NULL ) != ak_true ) {
        /* инициализация выполнена не успешно, следовательно, выходим из программы */
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    char data[128] = "test data for hash";

    struct hash ctx; /* Контекст функции хеширования */
    int error = ak_error_ok;
    bool_t result = ak_true;
    int audit = ak_log_get_level();

    /* Буффер длиной 64 байта (512 бит) для получения результата */
    ak_uint8 out[64], buffer[512], *ptr = buffer;


    if(( error = ak_hash_create_oid(&ctx , ak_oid_find_by_name("streebog512"))) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong initialization of streebog512 context" );
      return ak_false;
    }

    /* Инициализируем контекст функции хешиирования по oid*/
    /* Возможные значения oid для хеширования:
        "streebog512"
        "streebog256"
        "md_gost12_512"
        "md_gost12_256"
        "1.2.643.7.1.1.2.2" - идентификатор для алгоритма streebog256
        "1.2.643.7.1.1.2.3" - идентификатор для алгоритма streebog512
    Все OID аналогичны заданию функции напрямую */

    /* берем хеш от строки data */
    ak_hash_ptr( &ctx, data, sizeof(data), out, sizeof( out ));
    if(( error = ak_error_get_value()) != ak_error_ok ) {
        ak_error_message( error, __func__ , "invalid calculation of streebog512 code" );
        result = ak_false;
    }
    //выводим
    for (int i=0;i<sizeof(out);i++){
        printf("%c", out[i]);
    }
    
    ak_hash_destroy(&ctx);
    ak_libakrypt_destroy();
    return EXIT_SUCCESS;
    
} 
