/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий внутренние механизмы библиотеки для
   инициализации ключей блочного шифрования и реализации различных методов присвоения ключам
   секретных значений (на примере блочного шифра Магма).
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <ak_tools.h>
 #include <ak_bckey.h>
 #include <ak_parameters.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/* Функция вывода в консоль подробной информации о секретном ключе */
 void print_bckey( ak_bckey bkey );

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
 char *str = NULL;
 ak_bckey first = NULL; /* контекст ключа */
 int i, error = ak_error_ok;
 ak_random generator = NULL;
 ak_uint32 key[8] = { 0x11, 0x2200, 0x330000, 0x44000000, 0xaa, 0xbb00, 0xcc0000, 0xdd000000 };
 char password[64];

 /* 1. инициализируем библиотеку */
  ak_libakrypt_create( ak_function_log_stderr );

 /* 2. создаем генератор псевдо-случайных чисел */
  if(( error = ak_random_create_lcg( generator = malloc( sizeof( struct random )))) != ak_error_ok ) {
    free( generator );
    return ak_libakrypt_destroy();
  }

 /* 3. создаем пустой контекст ключа */
  if(( error = ak_bckey_create_magma( first = malloc( sizeof( struct bckey )))) != ak_error_ok ) {
    free( first );
    return ak_libakrypt_destroy();
  } else print_bckey( first );
  printf("\n");

 /* 4. присваиваем ключу константное значение,
    параметр ak_false означает, что данные не копируются,
    а физически остаются в переменной key */
  if( ak_bckey_context_set_ptr( first, key, 32, ak_false ) != ak_error_ok )
    printf("wrong assigning a constant key value\n");
   else print_bckey( first );
  /* что здесь? легко увидеть */
  printf("  memory: %s\n\n", str = ak_ptr_to_hexstr( &key, 32, ak_false )); free( str );

 /* 5. выводим последовательность, которую должен выработать генератор */
  generator->randomize_ptr( generator, key, 32 );
  printf("  random: ");
  for( i = 0; i < 8; i++ ) {
     ak_uint32 ch;
     generator->random( generator, &ch, 4 );
     printf("%08x", ch );
  }
  /* устанавливаем генератор в начальное состояние */
  generator->randomize_ptr( generator, key, 32 );
  printf("\n\n");

 /* 6. не удаляя старое значение ключа, присваиваем новое, как бы случайное.
    при этом используется память, выделенная при инициализации.
    В нашем случае, из за смены области памяти при вызове предыдущей функции,
    используется внешняя память key, в которой когда-то была фиксированная константа ... */
  if( ak_bckey_context_set_random( first, generator ) != ak_error_ok )
    printf("wrong assigning a constant key value\n");
   else print_bckey( first );
  /* еще раз: что здесь? (данные в массиве key многократно переписываются без всяких сомнений) */
  printf("  memory: %s\n", str = ak_ptr_to_hexstr( &key, 32, ak_false )); free( str );

 /* 7. повторяем процедуру еще раз, теперь с ключом из пароля */
  printf("\npassword: "); fflush( stdout );
  if( ak_password_read( password, 64 ) != ak_error_ok ) goto exit;
   else printf(" (password: %s, len: %lu, salt: salt, len: 4, count: %d)\n",
                    password, strlen( password ), ak_libakrypt_get_option("pbkdf2_iteration_count"));
  if( ak_bckey_context_set_password( first, password, strlen(password), "salt", 4 ) != ak_error_ok )
    printf("wrong generation a key from password\n");
   else print_bckey( first );
  /* в последний раз */
  printf("  memory: %s\n\n", str = ak_ptr_to_hexstr( &key, 32, ak_false )); free( str );

 /* 8. освобождаем память и завершаем работу программы */
  exit:
  generator = ak_random_delete( generator );
  first = ak_bckey_delete( first );
 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 void print_bckey( ak_bckey bkey )
{
  char *str = NULL;

  printf("key ---> %s (%s)\n",
                 ak_buffer_get_str( &bkey->key.oid->name ), ak_buffer_get_str(& bkey->key.oid->id ));
  printf("  number: %s\n", ak_buffer_get_str( &bkey->key.number ));
  printf("   flags: %016llx\n", bkey->key.flags );
  printf(" counter: %016llx (%llu)\n", bkey->key.resource.counter, bkey->key.resource.counter );
  printf("     key: %s\n", str = ak_ptr_to_hexstr( bkey->key.key.data, 32, ak_false )); free( str );
  printf("    mask: %s\n", str = ak_ptr_to_hexstr( bkey->key.mask.data, 32, ak_false )); free( str );
 /* real key? */
  printf("real key: ");
  if( bkey->key.set_mask == ak_skey_set_mask_additive ) { /* снимаем аддитивную маску и получаем ключ */
    int idx = 0;
    for( idx = 0; idx < 8; idx++ ) printf("%08x",
     (ak_uint32)(((ak_uint32 *)bkey->key.key.data)[idx] - ((ak_uint32 *)bkey->key.mask.data)[idx]) );
  }
  printf("\n   icode: %s", str = ak_ptr_to_hexstr( bkey->key.icode.data, 8, ak_false )); free( str );
  if( bkey->key.check_icode( &bkey->key )) printf(" is Ok\n");
   else printf(" is Wrong\n");

  printf(" ivector: %s\n", str = ak_buffer_to_hexstr( &bkey->ivector )); free( str );
}

/* ----------------------------------------------------------------------------------------------- */
