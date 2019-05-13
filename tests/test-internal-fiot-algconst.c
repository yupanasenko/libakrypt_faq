/* Пример, иллюстрирующий взаимосвязь констант, определяющих криптографические механизмы,
   с константами, определяющими блочные шифры, функции выработки имитовставки и типы ключей.
   Внимание! Используются неэкспортируемые функции библиотеки.

   test-internal-fiot-constants.c
*/
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ak_fiot.h>

 int main( void )
{
  int idx = 0;
  struct desc {
   crypto_mechanism_t c;
   char *str;
  } m[17] = {
    { not_set_mechanism, "not_set_mechanism" },
    { streebog256, "streebog256" },
    { streebog512, "streebog512" },
    { magmaGOST3413ePSK, "magmaGOST3413ePSK" },
    { kuznechikGOST3413ePSK, "kuznechikGOST3413ePSK" },
    { magmaGOST3413iPSK, "magmaGOST3413iPSK" },
    { kuznechikGOST3413iPSK, "kuznechikGOST3413iPSK" },
    { hmac256ePSK, "hmac256ePSK" },
    { hmac512ePSK, "hmac512ePSK" },
    { hmac256iPSK, "hmac256iPSK" },
    { hmac512iPSK, "hmac256iPSK" },
    { magmaCTRplusHMAC256, "magmaCTRplusHMAC256" },
    { magmaCTRplusGOST3413, "magmaCTRplusGOST3413" },
    { kuznechikCTRplusHMAC256, "kuznechikCTRplusHMAC256" },
    { kuznechikCTRplusGOST3413, "kuznechikCTRplusGOST3413" },
    { magmaAEAD, "magmaAEAD" },
    { kuznechikAEAD, "kuznechikAEAD" },
  };

  for( idx = 0; idx < 17; idx++ ) {
     printf("mechanism: %4x -> cipher: %u, encryption_mode: %u, integrity func: %d, key type: %d [%s]\n",
      m[idx].c,
      ak_fiot_get_block_cipher(m[idx].c),
      ak_fiot_get_block_cipher_encryption(m[idx].c),
      ak_fiot_get_integrity_function(m[idx].c),
      ak_fiot_get_key_type(m[idx].c),
      m[idx].str
     );
  }

  printf("\n restrictions (named constants and values)\n");
  printf("baseKeyMechanismMagma: 0x%x\n", baseKeyMechanismMagma );
  printf("baseKeyMechanismKuznechik: 0x%x\n", baseKeyMechanismKuznechik );
  printf("shortKCMechanismMagma: 0x%x\n", shortKCMechanismMagma );
  printf("shortKCMechanismKuznechik: 0x%x\n", shortKCMechanismKuznechik );
  printf("longKCMechanismMagma: 0x%x\n", longKCMechanismMagma );
  printf("longKCMechanismKuznechik: 0x%x\n", longKCMechanismKuznechik );
  printf("shortKAMechanismMagma: 0x%x\n", shortKAMechanismMagma );
  printf("shortKAMechanismKuznechik: 0x%x\n", shortKAMechanismKuznechik );
  printf("longKAMechanismMagma: 0x%x\n", longKAMechanismMagma );
  printf("longKAMechanismKuznechik: 0x%x\n", longKAMechanismKuznechik );

 return EXIT_SUCCESS;
}
