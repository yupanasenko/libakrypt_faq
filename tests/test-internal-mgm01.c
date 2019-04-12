/* Тестовый пример, иллюстрирующий работу режима шифрования с аутентификацией.

   Пример использует неэкспортируемые функции.

   test-internal-mgm01.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_mgm.h>

/* общие данные */
 static ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 static ak_uint8 associated[41] = {
     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA };

 static ak_uint8 plain[67] = {
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0xCC, 0xBB, 0xAA };

 static ak_uint8 iv128[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };

 static ak_uint8 icodeOne[16] = {
    0x4C, 0xDB, 0xFC, 0x29, 0x0E, 0xBB, 0xE8, 0x46, 0x5C, 0x4F, 0xC3, 0x40, 0x6F, 0x65, 0x5D, 0xCF };

 int main( void )
{
  char st[512];
  ak_bool result;
  struct bckey key; /* ключ блочного алгоритма шифрования */
  ak_uint8 frame[124];

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* формируем фрейм */
  memcpy( frame, associated, sizeof ( associated ));        /* ассоциированные данные */
  memcpy( frame + sizeof( associated ), plain, sizeof( plain ));  /* шифруемые данные */
  memset( frame + ( sizeof( associated ) + sizeof( plain )), 0, 16 ); /* имитовставка */

 /* инициализируем ключ */
  ak_bckey_context_create_kuznechik( &key );
  ak_bckey_context_set_key( &key, keyAnnexA, sizeof( keyAnnexA ), ak_true );

 /* зашифровываем данные и одновременно вычисляем имитовставку */
  ak_bckey_context_encrypt_mgm(
    &key,              /* ключ, используемый для шифрования данных */
    &key,             /* ключ, используемый для имитозащиты данных */
    frame,                  /* указатель на ассоциированные данные */
    sizeof( associated ),          /* длина ассоциированных данных */
    plain,                  /* указатель на зашифровываемые данные */
    frame + sizeof( associated ),   /* указатель на область памяти,
                         в которую помещаются зашифрованные данные */
    sizeof( plain ),              /* размер зашифровываемых данных */
    iv128,             /* синхропосылка (инициализационный вектор) */
    sizeof( iv128 ),                       /* размер синхропосылки */
                                    /* указатель на область памяти,
                                 в которую помещается имитовставка */
    frame + sizeof( associated ) + sizeof( plain ),
    16                                      /* размер имитовставки */
  );

 /* выводим результат и проверяем полученное значение */
  ak_ptr_to_hexstr_static( frame, sizeof( frame ), st, sizeof( st ), ak_false );
  printf("encrypted frame: %s [", st );
  if( memcmp( frame + sizeof( associated ) + sizeof( plain ), icodeOne, 16 )) {
    printf("Wrong]\n");
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  } else printf("Ok]\n\n");

 /* расшифровываем и проверяем имитовставку */
  result = ak_bckey_context_decrypt_mgm(
    &key,           /* ключ, используемый для расшифрования данных */
    &key,             /* ключ, используемый для имитозащиты данных */
    frame,                  /* указатель на ассоциированные данные */
    sizeof( associated ),          /* длина ассоциированных данных */
                           /* указатель на расшифровываемые данные */
    frame + sizeof( associated),
    frame + sizeof( associated ),   /* указатель на область памяти,
                        в которую помещаются расшифрованные данные */
    sizeof( plain ),              /* размер зашифровыванных данных */
    iv128,             /* синхропосылка (инициализационный вектор) */
    sizeof( iv128 ),                       /* размер синхропосылки */
                                    /* указатель на область памяти,
                в которой находится вычисленная ранее имитовставка
                       (с данным значением производится сравнение) */
    frame + sizeof( associated ) + sizeof( plain ),
    16                                      /* размер имитовставки */
  );

  ak_ptr_to_hexstr_static( frame, sizeof( frame ), st, sizeof( st ), ak_false );
  printf("decrypted frame: %s [", st );
  if( result ) printf("Correct]\n");
    else printf("Incorrect]\n");

 /* уничтожаем контекст ключа */
  ak_bckey_context_destroy( &key );
  ak_libakrypt_destroy();

 if( result == ak_true ) return EXIT_SUCCESS;
  else return EXIT_FAILURE;
}
