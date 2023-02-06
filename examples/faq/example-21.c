#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

/*Пример проверки электронной подписи*/

int main( void ) 
{
    if( ak_libakrypt_create( NULL ) != ak_true ) {
        /* инициализация выполнена не успешно, следовательно, выходим из программы */
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    
    /*контекст секретного ключа электронной подписи*/
    struct signkey sk;
    
    /*контекст открытого ключа электронной подписи*/
    struct verifykey pk;
    
    struct random generator;
 
    /*значение секретного ключа*/
    ak_uint8 testkey[32] = {
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 
        0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 
        0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 
        0x99, 0x28 
    };
    
    /* выставление третьего максимального уровень аудита */
    ak_log_set_level(ak_log_maximum);

    /* создаем генератор псевдо-случайных последовательностей */
    if (ak_random_create_lcg(&generator) != ak_error_ok)
        return ak_error_get_value();

    /* инициализация секретного ключа, заданного эллиптической кривой */
    if (ak_signkey_create_str(&sk, "cspa" /* строка, содержащая имя или идентификатор 
    	эллиптической кривой, на которой будет реализован криптографический алгоритм */
     					 )!= ak_error_ok)
        return ak_error_get_value();    

    /* устанавливаем значение ключа */
    if(ak_signkey_set_key(
    			&sk, /* контекст секретного ключа алгоритма электронной подписи */
    			testkey, /* указатель на область памяти, содержащей значение 
    			секретного ключа */
    			sizeof(testkey) /* размер ключа в байтах */
    					) != ak_error_ok)
        return ak_error_get_value();

    /* подстраиваем ключ и устанавливаем ресурс */
    ak_skey_set_resource_values(&sk.key, key_using_resource,
        "digital_signature_count_resource", 0, time(NULL) + 2592000);

    /*даннные для подписи*/
    char data[] = "data for signed";
    
    /*под ЭП*/
    ak_pointer sign[128];
    
    
    /* подписываем данные, в качестве которых выступает строка данных */
    ak_signkey_sign_ptr(
    			&sk, /* контекст секретного ключа алгоритма электронной подписи */
    			&generator, /* генератор случайной последовательности,
    			используемой в алгоритме подписи */
    			data, /* указатель на входные данные которые подписываются */
    			sizeof(data), /* размер входных данных в байтах */
    			sign, /* область памяти, куда будет помещена ЭП */
    			sizeof(sign) /* размер выделенной под выработанную ЭП памяти */
    			);

    /* инициализируем контекст открытого ключа и вычисляем его значение
    (точку эллиптической кривой), соответствующее заданному значению секретного ключа*/
    ak_verifykey_create_from_signkey(&pk, &sk);
    
    /* проверяем правильность подписи */
    if (ak_verifykey_verify_ptr(
    			&pk, /* контекст открытого ключа */
    			data, /* область памяти для которой проверяется электронная подпись */
    			sizeof(data), /* размер области памяти в байтах */
    			sign /* электронная подпись, для которой выполняется проверка */
    		 			) == ak_true)
        printf("verify: Ok\n");
    else {
        printf("verify: Wrong\n");
        return ak_error_get_value();
    }

    ak_signkey_destroy(&sk);
    ak_verifykey_destroy(&pk);
    ak_random_destroy(&generator);
    ak_libakrypt_destroy();
    return EXIT_SUCCESS;
}
