/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_key_manager.c                                                                          */
/*  - содержит реализацию функций для менеджера ключей.                                            */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>
 #include <ak_key_manager.h>
 #include <ak_asn1_keys.h>

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
/* реализация базового менеджера ключей, использующего хранение в файлах в заданном каталоге       */
/* ----------------------------------------------------------------------------------------------- */
/*! Класс, уточняющий строение области статической памяти менеджера ключей. */
 typedef struct key_manager_directory {
  /*! \brief Имя каталога  */
   char directory[key_manager_blob_size];

} *ak_key_manager_directory;

/* ----------------------------------------------------------------------------------------------- */
 #ifdef _WIN32
  #define ak_key_manager_separator                ("\\")
 #else
  #define ak_key_manager_separator                 ("/")
 #endif
  #define ak_key_manager_index_filename  (".index.file")

/* ----------------------------------------------------------------------------------------------- */
 static int ak_key_manager_add_container_to_directory( ak_key_manager km,
                                            const char *container , crypto_content_t content_type )
{
  struct file f;
  int error = ak_error_ok;
  struct container_info ci;
  char filename[FILENAME_MAX];
  ak_asn1 asn = NULL, basicKey = NULL, content = NULL;
  ak_key_manager_directory blob = (ak_key_manager_directory) km->blob;

  if( container == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to container's filename" );
 /* проверяем, есть ли файл с заданным именем */
  if( ak_file_open_to_read( &f, container ) != ak_error_ok ) {
    return ak_error_message_fmt( ak_error_file_exists, __func__,
                                                       "the container %s don't exist", container );
  } else ak_file_close( &f );

 /* проверяем, есть ли в каталоге с ключами файл с таким же именем */
  ak_snprintf( filename, sizeof( filename ), "%s%s%s", blob->directory,
                                                             ak_key_manager_separator, container );
  if( ak_file_open_to_read( &f, filename ) == ak_error_ok ) {
    ak_file_close( &f );
    return ak_error_message_fmt( ak_error_file_exists, __func__,
                                                     "the container %s alredy exists", container );
  } else ak_error_set_value( ak_error_ok );

 /* следующие действия мы делаем для того, чтобы понять что именно к нам поступило
                     готовый контейнер копируем, а другие форматы - перепаковываем */
 /* для начала считываем ключ и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_context_import_from_file( asn = ak_asn1_context_new(),
                                                                   container )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                    "incorrect reading of ASN.1 context from %s file", container );
     goto lab1;
  }

 /* проверяем контейнер на формат хранящихся данных */
  ak_asn1_context_first( asn );
  if( !ak_tlv_context_check_libakrypt_container( asn->current, &basicKey, &content )) {
    /* переданный нам файл не является контейнером библиотеки */
     ak_error_message_fmt( error = ak_error_undefined_function, __func__,
                             "the given file is not valid container for storing data", container );
    /* TODO: здесь должен быть код, который помещает сертификат открытого ключа в контейнер */
     goto lab1;

  } else {

     /* файл распознан и теперь можно получить данные о ключе: тип ключа, ресурс и т.п. */
      switch( content_type = ak_asn1_context_get_content_type( content )) {
        case symmetric_key_content:
          if(( error = ak_asn1_context_get_symmetric_key_info( content, &ci )) != ak_error_ok ) {
            ak_error_message( error, __func__, "incorrect reading a symmetric key info" );
            goto lab1;
          }
          break;

        case secret_key_content:
          if(( error = ak_asn1_context_get_secret_key_info( content, &ci )) != ak_error_ok ) {
            ak_error_message( error, __func__, "incorrect reading a symmetric key info" );
            goto lab1;
          }
          break;

        default: ak_error_message( error = ak_error_invalid_asn1_content,
                                                                 __func__,  "incorrect key type" );
          goto lab1;
          break;
      } /* конец switch */

  } /* конец else */

 /* копируем файл с ключевой информацией */
  if( rename( container, filename ) != 0 ) {
    ak_error_message_fmt( ak_error_file_rename, __func__,
                              "the container cannot be removed to %s directory", blob->directory );
    goto lab1;
  }

 /* изменяем индексный файл */
  ak_snprintf( filename, sizeof( filename ), "%s%s%s", blob->directory,
                                         ak_key_manager_separator, ak_key_manager_index_filename );
 // ak_file_open_to_append( f, filename );
 // f <- [имя файла]

 printf("[%s]\nalias: %s\n", container, ci.alias );

// */
// /* надо
// // ини-файлы готовы, можно работать с заголовками
//     1. открыть таблицу с файлами
//     2. найти имя контейнера,
//        если уже есть, то вернуть ошибку
//     3. добавить новую строку вида
//          [имя файла]
//            alias = [пользовательское описание]
//            type = []
//            владелец = [] ?
//            ресурс = [] ?
//     4. скопировать файл
//   */

   lab1:
    if( asn != NULL ) ak_asn1_context_delete( asn );
    if( ci.alias != NULL ) free( ci.alias );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_key_manager_context_check_index_in_directory( ak_key_manager km )
{
  struct file f;
  int error = ak_error_ok;
  char filename[FILENAME_MAX];
  ak_key_manager_directory blob = (ak_key_manager_directory) km->blob;

  ak_snprintf( filename, sizeof( filename ), "%s%s%s", blob->directory,
                                         ak_key_manager_separator, ak_key_manager_index_filename );
  if( ak_file_open_to_read( &f, filename ) == ak_error_ok ) {
    ak_file_close( &f );
    return ak_error_ok;
  }
  if(( error = ak_file_create_to_write( &f, filename )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__, "incorrect creation of %s", filename );
   else ak_file_close( &f );

 return ak_error_ok;
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
 int ak_key_manager_context_create_in_directory( ak_key_manager km, const char *directory )
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

 /* проверяем наличие индексного файла */
  if(( error = ak_key_manager_context_check_index_in_directory( km )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of index file" );

 /* устанавливаем указатели на функции */
  km->add_container = ak_key_manager_add_container_to_directory;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/* ----------------------------------------------------------------------------------------------- */
 int ak_key_manager_context_destroy( ak_key_manager km )
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
