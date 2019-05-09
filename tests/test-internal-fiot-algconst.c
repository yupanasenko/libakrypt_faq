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
  crypto_mechanism_t m;

 /* вывод/проверка значений предустановленных констант криптографических алгоритмов */
  m = not_set_mechanism;
  printf("not_set_mechanism: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = streebog256;
  printf("streebog256: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = streebog512;
  printf("streebog256: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = magmaGOST3413ePSK;
  printf("magmaGOST3413ePSK: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = kuznechikGOST3413ePSK;
  printf("kuznechikGOST3413ePSK: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = magmaGOST3413iPSK;
  printf("magmaGOST3413iPSK: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = kuznechikGOST3413iPSK;
  printf("kuznechikGOST3413iPSK: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = hmac256ePSK;
  printf("hmac256ePSK: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = hmac256iPSK;
  printf("hmac256iPSK: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = hmac512ePSK;
  printf("hmac512ePSK: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = hmac512iPSK;
  printf("hmac512iPSK: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = magmaCTRplusHMAC256;
  printf("magmaCTRplusHMAC256: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = magmaCTRplusGOST3413;
  printf("magmaCTRplusGOST3413: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = kuznechikCTRplusHMAC256;
  printf("kuznechikCTRplusHMAC256: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = kuznechikCTRplusGOST3413;
  printf("kuznechikCTRplusGOST3413: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = magmaAEAD;
  printf("magmaAEAD: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

  m = kuznechikAEAD;
  printf("kuznechikAEAD: %x -> cipher: %u, integrity func: %d, key type: %d\n",
   m, ak_fiot_get_block_cipher(m), ak_fiot_get_integrity_function(m), ak_fiot_get_key_type(m));

 return EXIT_SUCCESS;
}
