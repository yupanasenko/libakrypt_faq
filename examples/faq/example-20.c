#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

/* Пример использования электронной подписи на основе вычисленного хеш-кода 
			подписываемого сообщения */

int main( void ) 
{
	if( ak_libakrypt_create( NULL ) != ak_true ) {
		/* инициализация выполнена не успешно, следовательно, выходим из программы */
		ak_libakrypt_destroy();
		return EXIT_FAILURE;
  	}
	
    /* контекст секретного ключа электронной подписи */
    struct signkey sk;
    struct random generator;
    
    /* выставление третьего максимального уровень аудита */
    ak_log_set_level(ak_log_maximum);

    /* создаем генератор псевдо-случайных последовательностей */
    if (ak_random_create_lcg(&generator) != ak_error_ok)
        return ak_error_get_value();

    if (ak_error_ok != ak_random_create_oid(&generator, ak_oid_find_by_name("lcg")))
        return ak_error_get_value();
	
    /* Возможные значения OID для aead шифрования:
    
    "lcg"
    "dev-random"
    "dev-urandom"
    "winrtl"
    "nlfs"
    
    Все OID аналогичны заданию функции напрямую */

    /* инициализация секретного ключа, заданного эллиптической кривой */
    if (ak_signkey_create_str(&sk, "cspa" /* строка, содержащая имя или идентификатор 
    	эллиптической кривой, на которой будет реализован криптографический алгоритм */
     					 )!= ak_error_ok)
        return ak_error_get_value();    

    /* устанавливаем значение ключа */
    if(ak_signkey_set_key_random(
    			&sk, /* контекст секретного ключа алгоритма электронной подписи */
    			&generator /*контекст генератора случайных чисел*/
 				   ) != ak_error_ok)
        return ak_error_get_value();

    /* подстраиваем ключ и устанавливаем ресурс */
    ak_skey_set_resource_values(&sk.key, key_using_resource, "digital_signature_count_resource", 
    			0, time(NULL) + 2592000);

    /* степень кратности точки \f$ P \f$; представляет собой вычет по модулю 
    \f$ q \f$ - порядка группы точек эллиптической кривой; */
    ak_uint64 k[] = { 8, 5, 4, 4, 2 };
    
    /* целое число, соотвествующее хеш-коду подписываемого сообщения,
    заранее приведить значение по модулю `q` не требуется */
    ak_uint64 e[] = { 5, 4, 2, 1, 4 };
    
    /* под ЭП */
    ak_pointer out[128];
    
    /* подписываем данные вычисленного хеш-кода подписываемого сообщения */
    ak_signkey_sign_const_values(
    			&sk, /* контекст секретного ключа алгоритма электронной подписи */
    			k, /* степень кратности точки \f$ P \f$ */
    			e, /* целое число, соотвествующее хеш-коду подписываемого сообщения */
    			out /* массив, куда помещается результат */
    			);

    /* Подробнее про математическую составляющую данной процедуры можно почиать в папке source в файле ak_sign.c */

    ak_signkey_destroy(&sk);
    ak_random_destroy(&generator);
    ak_libakrypt_destroy();

    return EXIT_SUCCESS;
}
