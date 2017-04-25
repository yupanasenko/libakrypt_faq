/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2016 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_random.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_random.h>
 #include <time.h>
 #include <fcntl.h>
 #ifndef _WIN32
  #include <unistd.h>
 #endif
 #include <sys/stat.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация генератора псевдо-случайных чисел.

    Функция устанавливает значение полей структуры struct random в значения по-умолчанию.

    @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create( ak_random rnd )
{
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  rnd->data = NULL;
  rnd->next = NULL;
  rnd->randomize = NULL;
  rnd->randomize_uint64 = NULL;
  rnd->randomize_ptr = NULL;
  rnd->uint8 = NULL;
  rnd->uint64 = NULL;
  rnd->random = NULL;
  rnd->free = free;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание генератора псевдо-случайных чисел.

    Функция создает указатель на структуру struct random, устанавливает поля этой структуры
    в значения по-умолчанию и возвращает указатель на созданную структуру.
    @return Если указатель успешно создан, то он и возвращается. В случае возникновения ошибки
    возвращается NULL.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_random ak_random_new( void )
{
  ak_random rnd = ( ak_random ) malloc( sizeof( struct random ));
  if( rnd != NULL ) ak_random_create( rnd );
   else ak_error_message( ak_error_out_of_memory, __func__ , "incorrect memory allocation" );
  return rnd;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция уничтожает все данные, хранящиеся в полях структуры struct random.

    @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_destroy( ak_random rnd )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ ,"use a null pointer to a random generator" );
  return ak_error_null_pointer;
  }
  if( rnd->data != NULL ) rnd->free( rnd->data );
  rnd->next = NULL;
  rnd->randomize = NULL;
  rnd->randomize_uint64 = NULL;
  rnd->randomize_ptr = NULL;
  rnd->uint8 = NULL;
  rnd->uint64 = NULL;
  rnd->random = NULL;
  rnd->free = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает все внутренние поля, уничтожает генератор псевдо-случайных чисел
    (структуру struct random) и присваивает указателю значение NULL.

    @param указатель на структуру struct random.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_random_delete( ak_pointer rnd )
{
  if( rnd != NULL ) {
   ak_random_destroy(( ak_random ) rnd );
   free( rnd );
  } else ak_error_message( ak_error_null_pointer, __func__ ,
                                            "use a null pointer to a random generator" );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_randomize( ak_random rnd )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
   return ak_error_null_pointer;
  }
  if( rnd->randomize != NULL ) return rnd->randomize( rnd );
  ak_error_message( ak_error_undefined_function, __func__ ,
                                                       "use a null pointer to a function pointer" );
  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @param value значение, которым инициализируется генератор
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_randomize_uint64( ak_random rnd, const ak_uint64 value )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
   return ak_error_null_pointer;
  }
  if( rnd->randomize_uint64 != NULL ) return rnd->randomize_uint64( rnd, value );
  ak_error_message( ak_error_undefined_function, __func__ ,
                                                       "use a null pointer to a function pointer" );
  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @param ptr указатель на данные
    @param size размер данных в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_randomize_ptr( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
   return ak_error_null_pointer;
  }
  if( rnd->randomize_ptr != NULL ) return rnd->randomize_ptr( rnd, ptr, size );
  ak_error_message( ak_error_undefined_function, __func__ ,
                                                       "use a null pointer to a function pointer" );
  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @return Функция возвращает псевдо случайное число.
    В случае возникновения ошибки устанавливается ее код, который может быть позднее получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 ak_random_uint8( ak_random rnd )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
   return 0; /* возвращение нуля есть неявный признак ошибки,
                                         явный -- контроль с помощью функции ak_error_get_value() */
  }
  if( rnd->uint8 != NULL ) return rnd->uint8( rnd );
  ak_error_message( ak_error_undefined_function, __func__ ,
                                            "use a null pointer to a function pointer" );
  return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @return Функция возвращает псевдо случайное число.
    В случае возникновения ошибки устанавливается ее код, который модет быть позднее получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_uint64( ak_random rnd )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
   return 0; /* возвращение нуля есть неявный признак ошибки,
                                         явный -- контроль с помощью функции ak_error_get_value() */
  }
  if( rnd->uint64 != NULL ) return rnd->uint64( rnd );
  ak_error_message( ak_error_undefined_function, __func__ ,
                                                       "use a null pointer to a function pointer" );
  return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @param ptr указатель на область памяти
    @param size размер памяти в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_ptr( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  if( rnd == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
   return ak_error_null_pointer;
  }
  if( rnd->random != NULL ) return rnd->random( rnd, ptr, size );
  ak_error_message( ak_error_undefined_function, __func__ ,
                                                       "use a null pointer to a function pointer" );
  return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
  static ak_uint32 shift_value = 0; // Внутренняя статическая переменная (счетчик вызовов)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вырабатывает случайное 64-х битное целое число.

    Функция использует для генерации случайного значения текущее время и прочие параметры.
    Несмотря на случайность вырабатываемого значения, функция не должна использоваться для
    генерации значений, для которых требуется криптографическая случайность. Это связано с
    достаточно прогнозируемым изменением значений функции при многократных повторных вызовах.

   \return Функция возвращает случайное число.                                                     */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_value( void )
{
  ak_uint64 vtme = time( NULL );
  ak_uint64 clk = clock();
#ifndef _WIN32
  ak_uint64 pval = getpid();
  ak_uint64 uval = getuid();
#else
  ak_uint64 pval = _getpid();
  ak_uint64 uval = 67;
#endif
  ak_uint64 value = ( shift_value += 11 )*125643267795740073LL + pval;
            value = ( value * 506098983240188723LL ) + 71331*uval + vtme;
  return value ^ clk;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_lcg                                       */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний линейного конгруэнтного генератора              */
 struct random_lcg {
  /*! \brief текущее значение внутреннего состояния генератора */
  ak_uint64 val;
};
 typedef struct random_lcg *ak_random_lcg;

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_next( ak_random rnd )
{
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  (( ak_random_lcg ) ( rnd->data ))->val *= 125643267795740073LL;
  (( ak_random_lcg ) ( rnd->data ))->val += 506098983240188723LL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_randomize( ak_random rnd )
{
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  (( ak_random_lcg ) ( rnd->data ))->val = ak_random_value();
 return rnd->next( rnd );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_randomize_uint64( ak_random rnd, const ak_uint64 value )
{
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  (( ak_random_lcg ) ( rnd->data ))->val = value;
 return rnd->next( rnd );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_randomize_ptr( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  size_t idx = 0;
  ak_uint8 *value = ptr;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to initial vector" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use initial vector with zero length" );
    return ak_error_null_pointer;
  }
  /* сначала начальное значение, потом цикл по всем элементам массива */
  (( ak_random_lcg ) ( rnd->data ))->val = value[idx];
  do {
        rnd->next( rnd );
        (( ak_random_lcg ) ( rnd->data ))->val += value[idx];
  } while( ++idx < size );
 return rnd->next( rnd );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 ak_random_lcg_uint8( ak_random rnd )
{
  ak_uint8 value = 0;
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return 0;
  }
 value = (ak_uint8) ((( ak_random_lcg ) ( rnd->data ))->val >> 16);
 rnd->next( rnd );
 return value;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_lcg_uint64( ak_random rnd )
{
  int i = 0;
  ak_uint64 value = 0;
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return 0;
  }
  for( i = 0; i < 8; i++ ) {
    value <<= 8;
    value += (ak_uint8) ((( ak_random_lcg ) ( rnd->data ))->val >> 16 );
    rnd->next( rnd );
  }
  return value;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_random_lcg_random( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  size_t i = 0;
  ak_uint8 *value = ptr;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to data" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use a data with zero length" );
    return ak_error_zero_length;
  }

  for( i = 0; i < size; i++ ) {
    value[i] = (ak_uint8) ((( ak_random_lcg ) ( rnd->data ))->val >> 16 );
    rnd->next( rnd );
  }
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Данный генератор вырабатывает последовательность внутренних состояний, удовлетворяющую
    линейному сравнению \f$ x_{n+1} \equiv a\cdot x_n + c \pmod{2^{64}}, \f$
    в котором константы a и c удовлетворяют равенствам
    \f$ a = 125643267795740073 \f$ и \f$ b = 506098983240188723. \f$

    Далее, последовательность внутренних состояний преобразуется в последовательность
    байт по следующему правилу
    \f$ \gamma_n = \displaystyle\frac{x_n - \hat x_n}{2^{24}} \pmod{256}, \f$
    где \f$\hat x_n \equiv x_n \pmod{2^{24}}. \f$

    \return Функция возвращает указатель на структуру struct random.
            В случае ошибки возвращается NULL.                                                     */
/* ----------------------------------------------------------------------------------------------- */
 ak_random ak_random_new_lcg( void )
{
  ak_random rnd = ak_random_new();
  if( rnd == NULL ) { ak_error_message( ak_error_out_of_memory, __func__ ,
                                  "incorrect memory allocation for a random generator" );
    return NULL;
  }
  if(( rnd->data = malloc( sizeof( struct random_lcg ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
           "incorrect memory allocation for an internal variables of random generator" );
    return ( rnd = ak_random_delete( rnd ));
  }
  rnd->next = ak_random_lcg_next;
  rnd->randomize = ak_random_lcg_randomize;
  rnd->randomize_uint64 = ak_random_lcg_randomize_uint64;
  rnd->randomize_ptr = ak_random_lcg_randomize_ptr;
  rnd->uint8 = ak_random_lcg_uint8;
  rnd->uint64 = ak_random_lcg_uint64;
  rnd->random = ak_random_lcg_random;
  /* функция rnd->free уже установлена */
  rnd->randomize( rnd ); /* для генерации случайных значений и корректной работы генератора
                                                 присваиваем какое-то случайное начальное значение */
 return rnd;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_file                                      */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний генератора-файла                                */
 struct random_file {
  /*! \brief файловый дескриптор */
  int fd;
};
 typedef struct random_file *ak_random_file;

/* ----------------------------------------------------------------------------------------------- */
 void ak_random_file_free( ak_pointer ptr )
{
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "freeing a null pointer to data" );
    return;
  }
  if( close( (( ak_random_file ) ptr )->fd ) == -1 )
    ak_error_message( ak_error_close_file, __func__ , "wrong closing a file with random data" );
  free(ptr);
}

/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 ak_random_file_uint8( ak_random rnd )
{
  size_t result = 0;
  ak_uint8 value = 0;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return 0;
  }
  /* считываем один байт */
  slabel:
  result = read( (( ak_random_file ) ( rnd->data ))->fd, &value, sizeof( ak_uint8 ));

  /* если конец файла, то переходим в начало */
  if( result == 0 ) {
    lseek( (( ak_random_file ) ( rnd->data ))->fd, 0, SEEK_SET );
    goto slabel;
  }
  /* если ошибка чтения, то возбуждаем ошибку */
  if( result == -1 ) {
    ak_error_message( ak_error_read_data, __func__ , "wrong reading data from file" );
    return 0;
  }
 return value;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_random_file_random( ak_random rnd, const ak_pointer ptr, const size_t size )
{
  ak_uint8 *value = ptr;
  size_t result = 0, count = size;

  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to data" );
    return ak_error_null_pointer;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "use a data with zero length" );
    return ak_error_zero_length;
  }

  /* считываем несколько байт */
  slabel:
  result = read( (( ak_random_file ) ( rnd->data ))->fd, value,
  #ifdef _MSC_VER
    (unsigned int)
  #endif
    count );

  /* если конец файла, то переходим в начало */
  if( result == 0 ) {
    lseek( (( ak_random_file ) ( rnd->data ))->fd, 0, SEEK_SET );
    goto slabel;
  }
  /* если мы считали меньше, чем надо */
  if( result < count ) {
    value += result;
    count -= result;
    goto slabel;
  }
  /* если ошибка чтения, то возбуждаем ошибку */
  if( result == -1 ) {
    ak_error_message( ak_error_read_data, __func__ , "wrong reading data from file" );
    return ak_error_read_data;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_file_uint64( ak_random rnd )
{
  ak_uint64 value = 0;
  if( rnd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a random generator" );
    return 0;
  }

  if( ak_random_file_random( rnd, &value, sizeof( ak_uint64 )) != ak_error_ok ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong reading a random data" );
    return 0;
  }
  return value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает генератор, считывающий случайные значения из заданного файла

    Данный генератор связывается с заданным файлом и возвращает содержащиеся в нем значения
    в качестве случайных чисел. Если данные в файле заканчиваются, то считывание начинается
    с начала файла.

    Основное назначение данного генератора - считывание данных из файловых устройств,
    таких как /dev/randon или /dev/urandom.

    \return Функция возвращает указатель на структуру struct random.
            В случае ошибки возвращается NULL.                                                     */
/* ----------------------------------------------------------------------------------------------- */
 ak_random ak_random_new_file( const char *filename )
{
  ak_random rnd = ak_random_new();
  if( rnd == NULL ) { ak_error_message( ak_error_out_of_memory, __func__ ,
                                  "incorrect memory allocation for a random generator" );
    return NULL;
  }
  if(( rnd->data = malloc( sizeof( struct random_file ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
           "incorrect memory allocation for an internal variables of random generator" );
    return ( rnd = ak_random_delete( rnd ));
  }

  /* теперь мы открываем заданный пользователем файл */
  if( ((( ak_random_file ) ( rnd->data ))->fd = open( filename, O_RDONLY | O_BINARY )) == -1 ) {
    ak_error_message( ak_error_open_file, __func__ , "wrong opening a file with random data" );
    return ( rnd = ak_random_delete( rnd ));
  }

  rnd->next = NULL;
  rnd->randomize =NULL;
  rnd->randomize_uint64 = NULL;
  rnd->randomize_ptr = NULL;
  rnd->uint8 = ak_random_file_uint8;
  rnd->uint64 = ak_random_file_uint64;
  rnd->random = ak_random_file_random;
  rnd->free = ak_random_file_free; /* эта функция должна закрыть открытый ранее файл */
 return rnd;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-random.c                                                                      */
/*! \example example-dev-random.c                                                                  */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_random.c  */
/* ----------------------------------------------------------------------------------------------- */
