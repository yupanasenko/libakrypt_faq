#include <stdio.h>
#include <libakrypt-base.h>
#include <libakrypt.h>

/*Пример вычисления 32-битной контрольной суммы с помощью модифицированного алгоритма Флетчера,
    заменяющего обычное модульное сложение на операцию поразрядного сложения по модулю 2*/
int main( void )
{ 
    if( ak_libakrypt_create( NULL ) != ak_true ) {
        /* инициализация выполнена не успешно, следовательно, выходим из программы */
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    
    ak_const_pointer data = "abcde";
    ak_uint32 *res;
    res = (ak_uint32*)malloc(1);
    res[0]=0;
    int result = ak_ptr_fletcher32_xor(data,5,res);

    int i=0;

    for(i=0;i<1;i++){
        printf("%d \n %d",res[i],result);
    }
    
    ak_libakrypt_destroy();
    return EXIT_SUCCESS;
    
}
