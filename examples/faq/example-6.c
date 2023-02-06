/* ----------------------------------------------------------------------------------- */
/* Пример example-6.c                                                             */
/* ----------------------------------------------------------------------------------- */
#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

int main(void) {
    if( ak_libakrypt_create( NULL ) != ak_true ) {
   /* инициализация выполнена не успешно, следовательно, выходим из программы */
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
  }
    /*Структура для хранения контекста ключа*/
    struct bckey ekey, ikey;

    static ak_uint8 keyAnnexA[32] = { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 
    	0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 
        0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 
    };  

    static ak_uint8 keyAnnexABlockReverse[32] = { 0x77, 0x66, 0x55, 0x44, 
    	0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 
    	0x99, 0x88, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    	0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe 
    };

    /*Инициализация контекста ключа алгоритма блочного шифрования Магма (ГОСТ Р 34.12-2015)*/
    ak_bckey_create_magma(&ekey); 
    
    /*Присваиваем констекту ключа ekey значение keyAnnexA*/
    ak_bckey_set_key(&ekey, keyAnnexA, sizeof(keyAnnexA)); 
    
    /*инициализация имитовставки*/
    ak_bckey_create_magma(&ikey);
    
    /*Присваиваем констекту ключа ikey значение keyAnnexABlockReverse*/
    ak_bckey_set_key(&ikey, keyAnnexABlockReverse, sizeof(keyAnnexABlockReverse));

    /*ассоциируемые данные*/
    static ak_uint8 associated[41] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
    	0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 
        0x05, 0x05, 0x05, 0x05, 0xEA 
    };
    /*зашифровываемые данные*/
    static ak_uint8 plain[67] = { 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 
    	0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x0A, 
    	0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 
    	0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 
    	0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 
    	0x11, 0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 
    	0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0xCC, 0xBB, 0xAA 
    };

    ak_uint8 ina_ptr[32 + sizeof(associated)], inp[32 + sizeof(plain)], otp[32 + sizeof(plain)];   
    ak_uint8 out_ptr[32 + sizeof(plain)], icode[16];
    void* inp_ptr = inp;
    void* otp_ptr = otp;

    int len = 8;
    
    static ak_uint8 iv128[16] = { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 
    			0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 
    };

    memcpy(ina_ptr, associated, sizeof(associated));    
    memcpy(inp_ptr, plain, sizeof(plain));

    if (ak_error_ok != ak_bckey_encrypt_xtsmac(
                    &ekey,               /*Ключ шифрования*/
                    &ikey,               /*Ключ выработки кода аутентификации (имитовставки)*/
                    ina_ptr,             /*Указатель на ассоциируемые данные*/
                    sizeof(associated),  /*Размер ассоциируемых данных в байтах*/
                    inp_ptr,             /*Указатель на зашифровываемые данные*/
                    otp_ptr,             /*Указатель на зашифрованные данные*/
                    len,                 /*Размер зашифровываемых данных в байтах, должен быть не менее 16 октетов*/
                    iv128,               /*Указатель на синхропосылку*/
                    sizeof(iv128),       /*Длина синхропосылки в байтах*/
                    icode,               /*Указатель на область памяти, куда будет помещено значение имитовставки*/
                    16                   /*Ожидаемый размер имитовставки в байтах; значение не должно превышать 16 октетов;*/
                    ))
        return ak_error_get_value();     
    ak_bckey_destroy(&ekey);
    ak_bckey_destroy(&ikey);
    ak_libakrypt_destroy();
    return EXIT_SUCCESS;
}
