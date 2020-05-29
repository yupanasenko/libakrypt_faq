/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_context_manager.c                                                                      */
/*  - содержит реализацию функций для менеджера ключей.                                            */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>
 #include <ak_key_manager.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#else
 #error Library cannot be compiled without errno.h header
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_FCNTL_H
 #include <fcntl.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #include <share.h>
 #include <direct.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/* реализация базового менеджера ключей, использующего хранение данных в файла в заданном каталоге */
/* ----------------------------------------------------------------------------------------------- */
/*! Класс, уточняющий строение области статической памяти менеджера ключей. */
 typedef struct key_manager_directory {
  /*! \brief Имя каталога  */
   char directory[key_manager_blob_size];

} *ak_key_manager_directory;

/* ----------------------------------------------------------------------------------------------- */
 int ak_key_manager_add_container_to_directory( const char *container , crypto_content_t content )
{

 /* надо
     1. открыть таблицу с файлами
     2. найти имя контейнера,
        если уже есть, то вернуть ошибку
     3. добавить новую строку вида
          [имя файла]
            alias = [пользовательское описание]
            type = []
            владелец = [] ?
            ресурс = [] ?
     4. скопировать файл
   */

 // ини-файлы готовы, можно работать с заголовками

 return ak_error_undefined_function;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст менеджера ключей, указывая ему каталог, в котором будет
   располагаться ключевая информация. Также следует учитывать следующие особенности реализации:

   - если у пользователя нет прав на чтение/запись в данный каталог, то будет возбуждена ошибка.
   - если вместо имени каталога передается `null`, то в качестве каталога расположения ключевой
   информации будет выбран пользовательский каталог библиотеки `libakrypt`
   (данная возможность реализуется только в случае, когда библиотека скомпилирована без флага
   `LIBAKRYPT_CONST_CRYPTO_PARAMS`).

   \param km контекст менеджера ключей
   \param directory каталог, в котором будет располагаться ключевая информация;
   \return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_key_manager_create_directory( ak_key_manager km, const char *directory )
{
 #ifndef _MSC_VER
  int d = 0;
 #endif
  char hpath[FILENAME_MAX];
  int error = ak_error_ok;
  ak_key_manager_directory blob = (ak_key_manager_directory) km->blob;

 /* неоходимые проверки */
  if( km == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to key manager" );
  memset( km, 0, sizeof( struct key_manager ));

#ifndef LIBAKRYPT_CONST_CRYPTO_PARAMS
  if( directory == NULL ) { /* формируем имя каталога, используя пользовательский
                                                    каталог библиотеки `libakrypt` */
    if(( error = ak_libakrypt_get_home_path( hpath, sizeof( hpath ))) != ak_error_ok )
      return ak_error_message( error, __func__, "wrong directory name creation" );

  #ifdef _WIN32
    ak_snprintf( blob->directory, sizeof( blob->directory ),
                                                           "%s\\.config\\libakrypt\\keys", hpath );
   #ifdef _MSC_VER
    if( _mkdir( blob->directory ) < 0 ) {
   #else
    if( mkdir( blob->directory ) < 0 ) {
   #endif
  #else
   ak_snprintf( blob->directory, sizeof( blob->directory ), "%s/.config/libakrypt/keys", hpath );
   if( mkdir( blob->directory, S_IRWXU ) < 0 ) {
  #endif
    if( errno != EEXIST ) {
     #ifdef _MSC_VER
     /* помещаем сообщение об ошибке в ненужный буффер */
       strerror_s( hpath, sizeof( hpath ), errno );
       return ak_error_message_fmt( ak_error_access_file, __func__,
                                   "wrong creation of %s directory [%s]", blob->directory, hpath );
     #else
      return ak_error_message_fmt( ak_error_access_file, __func__,
                        "wrong creation of %s directory [%s]", blob->directory, strerror( errno ));
     #endif
    }
   }
  } else
#else
  if( directory == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to directory for storing keys" );
#endif
     strncpy( blob->directory, directory, sizeof( blob->directory ));

  printf("blob->directory: %s\n", blob->directory );

 /* проверяем, что путь либо существует, либо у нас есть права, на его создание */
  #ifdef _MSC_VER
   ak_snprintf( hpath, sizeof( hpath ), "%s\\tempfile-XXXXXX", blob->directory );
  #else
   ak_snprintf( hpath, sizeof( hpath ), "%s/tempfile-XXXXXX", blob->directory );
  #endif
   printf("hpath: %s\n", hpath );

  #ifdef _MSC_VER
   if( _mktemp_s( hpath, sizeof( hpath )) != 0 )
     return ak_error_message( ak_error_access_file, __func__, "incorrect generation file name" );
    else {
      struct file fp;
      if(( error = ak_file_create_to_write( &fp, hpath )) != ak_error_ok )
        return ak_error_message_fmt( ak_error_access_file, __func__,
                                                "incorrect creation of temporary file %s", hpath );
      ak_file_close( &fp );
    }
  #else
   if(( d = mkstemp( hpath )) < 0 )
     return ak_error_message_fmt( ak_error_access_file, __func__,
      "incorrect creation of temporary file %s [%s]", hpath, strerror( errno ));
    else close(d);
  #endif
  remove( hpath );

 /* устанавливаем указатели на функции */
  km->add_container = ak_key_manager_add_container_to_directory;

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
 int ak_key_manager_destroy( ak_key_manager km )
{
 /* неоходимые проверки */
  if( km == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to key manager" );
  memset( km, 0, sizeof( struct key_manager ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                               ak_key_manager.c  */
/* ----------------------------------------------------------------------------------------------- */
