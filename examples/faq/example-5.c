#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

int main() {
    struct bckey key;
    int error = ak_error_ok, audit = ak_log_get_level();
    
    ak_uint8 skey[32] = {
      		0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 
      		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
      		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 
      		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    		};
    		
    ak_uint8 iv1[8] = { 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12 };
    ak_uint8 iv2[4] = { 0x78, 0x56, 0x34, 0x12 };

    ak_uint8 out[112], in1[112] = {
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
      0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
      0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
      0x33, 0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
      0x44, 0x33, 0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55
    };
    ak_uint8 out1[112] = {
      0xb8, 0xa1, 0xbd, 0x40, 0xa2, 0x5f, 0x7b, 0xd5, 0xdb, 0xd1, 0x0e, 0xc1, 0xbe, 0xd8, 0x95, 0xf1,
      0xe4, 0xde, 0x45, 0x3c, 0xb3, 0xe4, 0x3c, 0xf3, 0x5d, 0x3e, 0xa1, 0xf6, 0x33, 0xe7, 0xee, 0x85,
      0x00, 0xe8, 0x85, 0x5e, 0x27, 0x06, 0x17, 0x00, 0x55, 0x4c, 0x6f, 0x64, 0x8f, 0xeb, 0xce, 0x4b,
      0x46, 0x50, 0x80, 0xd0, 0xaf, 0x34, 0x48, 0x3e, 0x39, 0x94, 0xd0, 0x68, 0xf5, 0x4d, 0x7c, 0x58,
      0x6e, 0x89, 0x8a, 0x6b, 0x31, 0x6c, 0xfc, 0x1c, 0xe1, 0xec, 0xae, 0x86, 0x76, 0xf5, 0x30, 0xcf,
      0x3e, 0x16, 0x23, 0x34, 0x74, 0x3b, 0x4f, 0x0c, 0x46, 0x36, 0x36, 0x81, 0xec, 0x07, 0xfd, 0xdf,
      0x5d, 0xde, 0xd6, 0xfb, 0xe7, 0x21, 0xd2, 0x69, 0xd4, 0xc8, 0xfa, 0x82, 0xc2, 0xa9, 0x09, 0x64
    };
    ak_uint8 in2[56] = {
      0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
      0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
      0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99,
      0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22
    };
    ak_uint8 out2[56] = {
      0xab, 0x4c, 0x1e, 0xeb, 0xee, 0x1d, 0xb8, 0x2a,
      0xea, 0x94, 0x6b, 0xbd, 0xc4, 0x04, 0xe1, 0x68,
      0x6b, 0x5b, 0x2e, 0x6c, 0xaf, 0x67, 0x2c, 0xc7,
      0x2e, 0xb3, 0xf1, 0x70, 0x17, 0xb6, 0xaf, 0x0e,
      0x82, 0x13, 0xed, 0x9e, 0x14, 0x71, 0xae, 0xa1,
      0x6f, 0xec, 0x72, 0x06, 0x18, 0x67, 0xd4, 0xab,
      0xc1, 0x72, 0xca, 0x3f, 0x5b, 0xf1, 0xa2, 0x84
    };

    /*Инициализация секретного ключа алгоритма блочного шифрования Магма*/
    if(ak_error_ok != ak_bckey_create_magma(&key))
        return ak_error_get_value();
    
    /* Инициализация контекста ключа значением, содержащимся в области памяти*/
    if(ak_error_ok != ak_bckey_set_key(&key, skey, sizeof(skey)))
        return ak_error_get_value();
   
    // шифруем
    if(ak_error_ok != ak_bckey_ctr_acpkm(
    		&key, /*Контекст ключа алгоритма блочного шифрования,
    		используемый для шифрования и порождения цепочки производных ключей.*/
    		in2, /*Указатель на область памяти, где хранятся входные
    		(зашифровываемые/расшифровываемые) данные*/
    		out, /*Указатель на область памяти, куда помещаются выходные данные*/
    		sizeof(in2), /*азмер зашировываемых данных (в байтах). Длина зашифровываемых данных может
    		принимать любое значение, не превосходящее \f$ 2^{\frac{8n}{2}-1}\f$, где \f$ n \f$
    		длина блока алгоритма шифрования (8 или 16 байт).*/
    		16, /*Размер одной секции в байтах. Данная величина должна быть кратна длине блока
    		используемого алгоритма шифрования.*/
    		iv2, /*имитовставка*/
    		sizeof(iv2) /*длина имитовсавки в байтах*/
    		))
        return ak_error_get_value();

    if (memcmp(out, out2, sizeof(in2)) != 0) {
        ak_error_message(ak_error_not_equal_data, __func__, "incorrect data comparizon after acpkm encryption with magma cipher");
        return ak_error_not_equal_data;
    }

    return 0;
}
