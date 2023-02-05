#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

int main() {
    /*Структура для хранения контекста ключа*/
    struct bckey key;

    /*Значение контекстного ключа вырабатывается из данного пароля*/ 
    char password[128] = "password";
    /*Случайный вектор в виде строки символов*/
    char s[128] = "sugar";

    /*Инициализация секретного ключа алгоритма блочного шифрования по его OID (Магма)*/
    if (ak_error_ok != ak_bckey_create_oid(&key, ak_oid_find_by_name("magma")))
	return ak_error_get_value();	

    /*Присваивание значения, выработанного из заданного пароля, контексту ключа*/
    if(ak_error_ok != ak_bckey_set_key_from_password(
    &key, /*Контекст ключа алгоритма блочного шифрования*/
    password,  /*Пароль, представленный в виде строки символов*/
    strlen(password),  /*Длина пароля в байтах*/
    s, /*Случайный вектор, представленный в виде строки символов.*/
    strlen(s) /*Длина случайного вектора в байтах*/
    ))
	return ak_error_get_value(); 

    /*Синхропосылка*/
    ak_uint8 testkey[32] = { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 
    		             	0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 
    		             	0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 
    		             	0xcc, 0xbb, 0xaa, 0x99, 0x38 };

    /*Зашифровываемые данные*/
    ak_uint8 testdata[31] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
    				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xf1, 0xe2, 
    				0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 
    				0x4c, 0x3d, 0x2e, 0x1f };
   
    /*Область памяти, куда помещается зашифрованная строка*/
    ak_uint8 out[31];

    if(ak_error_ok != ak_bckey_ctr(
        	&key, /*Контекст ключа алгоритма блочного шифрования, на котором происходит 
        	зашифрование или расшифрование информации*/
        	testdata, /*Указатель на область памяти, где хранятся входные (открытые) данные*/
        	out, /*Указатель на область памяти, куда помещаются зашифрованные данные 
        	(может быть тем же указателем, что и указатель на открытые данные )*/
        	sizeof(testdata), /*Размер зашировываемых данных (в байтах)*/
        	testkey, /*Указатель на произвольную область памяти - синхропосылку. 
        	Область памяти не изменяется*/
        	sizeof(testkey) /*Длина синхропосылки в байтах*/
        	))
        return ak_error_get_value();

    ak_uint8 decrypt[31];
    if (ak_error_ok != ak_bckey_ctr(
    		&key, /*Контекст ключа алгоритма блочного шифрования, на котором происходит 
        	зашифрование или расшифрование информации*/
    		out, /*Указатель на область памяти, где хранятся входные (открытые) данные*/
    		decrypt, /*Указатель на область памяти, куда помещаются зашифрованные данные 
        	(может быть тем же указателем, что и указатель на открытые данные )*/
    		sizeof(out), /*Размер зашировываемых данных (в байтах)*/ 
    		testkey, /*Указатель на произвольную область памяти - синхропосылку. 
        	Область памяти не изменяется*/
    		sizeof(testkey) /*Длина синхропосылки в байтах*/
    		))
        return ak_error_get_value();

    if (!memcmp(testdata, decrypt, sizeof(decrypt))) {
        printf("Data sucessfully encrypt and decrypt\n");
        return 0;
    }

    return ak_error_not_equal_data;
}
