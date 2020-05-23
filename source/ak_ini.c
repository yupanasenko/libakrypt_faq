/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2009-2020, Ben Hoyt, https://github.com/benhoyt/inih                             */
/*                                                                                                 */
/*  adopted for libakrypt by Axel Kenzo, axelkenzo@mail.ru                                         */
/*                                                                                                 */
/*  Файл ak_ini.h                                                                                  */
/*  - содержит описания чтения ini файлов                                                          */
/* ----------------------------------------------------------------------------------------------- */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

#ifdef LIBAKRYPT_HAVE_CTYPE_H
 #include <ctype.h>
#else
 #error Library cannot be compiled without ctype.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Множество символов с которых могут начинаться строки-комментарии. */
 #define INI_START_COMMENT_PREFIXES ";#"
/*! \brief Флаг разрешает использование комментариев, расположенных внутри строк с данными. */
 #define INI_ALLOW_INLINE_COMMENTS 1
/*! \brief Множество символов с которых могут начинаться комментарии, расположенные внутри строк с данными. */
 #define INI_INLINE_COMMENT_PREFIXES ";#"
/*! \brief Флаг остановки парсинга ini-файла после возникновения первой ошибки. */
 #define INI_STOP_ON_FIRST_ERROR 1
/*! \brief Флаг разрешает/запрещает использование полей без параметров. */
 #define INI_ALLOW_NO_VALUE 0

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Максимальное количество символов в одной строке (включая '\r', '\n', and '\0'). */
 #define INI_MAX_LINE 1024
/*! \brief Максимальный размер строки для имени секции. */
 #define INI_MAX_SECTION 256
/*! \brief Максимальный размер строки для имени. */
 #define INI_MAX_NAME 256

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, используемая ini_parse_string() для хранения текущего состояния. */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct {
    const char* ptr;
    size_t num_left;
} ini_parse_string_ctx;

/* ----------------------------------------------------------------------------------------------- */
/*! Strip whitespace chars off end of given string, in place. Return s. */
/* ----------------------------------------------------------------------------------------------- */
 static char* rstrip(char* s)
{
    char* p = s + strlen(s);
    while (p > s && isspace((unsigned char)(*--p)))
        *p = '\0';
    return s;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Return pointer to first non-whitespace char in given string. */
/* ----------------------------------------------------------------------------------------------- */
 static char* lskip(const char* s)
{
    while (*s && isspace((unsigned char)(*s)))
        s++;
    return (char*)s;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Return pointer to first char (of chars) or inline comment in given string,
   or pointer to null at end of string if neither found. Inline comment must
   be prefixed by a whitespace character to register as a comment. */
/* ----------------------------------------------------------------------------------------------- */
 static char* find_chars_or_comment(const char* s, const char* chars)
{
#if INI_ALLOW_INLINE_COMMENTS
    int was_space = 0;
    while (*s && (!chars || !strchr(chars, *s)) &&
           !(was_space && strchr(INI_INLINE_COMMENT_PREFIXES, *s))) {
        was_space = isspace((unsigned char)(*s));
        s++;
    }
#else
    while (*s && (!chars || !strchr(chars, *s))) {
        s++;
    }
#endif
    return (char*)s;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Version of strncpy that ensures dest (size bytes) is null-terminated. */
/* ----------------------------------------------------------------------------------------------- */
 static char* strncpy0( char* dest, const char* src, size_t size )
{
  size_t len = 0;

 /* используем медленное побайтное копирование с проверкой длины
    операция может привести к обрезанию исходной строки */
  memset( dest, 0, size );

  while(( len < size-1 ) && ( *src != 0 )) {
   dest[len] = src[len];
   ++len;
  }

 return dest;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Same as ini_parse(), but takes an ini_reader function pointer instead of
   filename. Used for implementing custom or string-based I/O (see also
   ini_parse_string). */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_ini_parse_stream( ini_reader reader, void* stream, ini_handler handler, void* user )
{
    char line[INI_MAX_LINE];
    int max_line = INI_MAX_LINE;
    char section[INI_MAX_SECTION] = "";
    char prev_name[INI_MAX_NAME] = "";

    char* start;
    char* end;
    char* name;
    char* value;
    int lineno = 0;
    int error = 0;

    /* Scan through stream line by line */
    while (reader(line, (int)max_line, stream) != NULL) {
        lineno++;

        start = line;
        start = lskip(rstrip(start));

        if (strchr(INI_START_COMMENT_PREFIXES, *start)) {
            /* Start-of-line comment */
        }
        else if (*start == '[') {
            /* A "[section]" line */
            end = find_chars_or_comment(start + 1, "]");
            if (*end == ']') {
                *end = '\0';
                strncpy0(section, start + 1, sizeof(section));
                *prev_name = '\0';
            }
            else if (!error) {
                /* No ']' found on section line */
                error = lineno;
            }
        }
        else if (*start) {
            /* Not a comment, must be a name[=:]value pair */
            end = find_chars_or_comment(start, "=:");
            if (*end == '=' || *end == ':') {
                *end = '\0';
                name = rstrip(start);
                value = end + 1;
#if INI_ALLOW_INLINE_COMMENTS
                end = find_chars_or_comment(value, NULL);
                if (*end)
                    *end = '\0';
#endif
                value = lskip(value);
                rstrip(value);

                /* Valid name[=:]value pair found, call handler */
                strncpy0( prev_name, name, sizeof( prev_name ));
                if( !handler(user, section, name, value) && !error)
                    error = lineno;
            }
            else if (!error) {
                /* No '=' or ':' found on name[=:]value line */
#if INI_ALLOW_NO_VALUE
                *end = '\0';
                name = rstrip(start);
                if (!handler(user, section, name, NULL) && !error)
                    error = lineno;
#else
                error = lineno;
#endif
            }
        }

#if INI_STOP_ON_FIRST_ERROR
        if( error ) break;
#endif
    }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Same as ini_parse(), but takes a FILE* instead of filename. This doesn't
    close the file when it's finished -- the caller must do that.

  \param file файловый дескриптор ini-файла
  \param handler функция-обработчик найденных значений
  \param user указатель на пользовательские данные
  \return В случае возникновения ошибки возвращается ее код. В случае успеха
   возвращается \ref ak_error_ok (ноль).                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_ini_parse_file( FILE* file, ini_handler handler, void* user )
{
    return ak_ini_parse_stream( (ini_reader)fgets, file, handler, user );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Parse given INI-style file. May have [section]s, name=value pairs
    (whitespace stripped), and comments starting with ';' (semicolon). Section
    is "" if name=value pair parsed before any section heading. name:value
    pairs are also supported as a concession to Python's configparser.

    For each name=value pair parsed, call handler function with given user
    pointer as well as section, name, and value (data only valid for duration
    of handler call). Handler should return nonzero on success, zero on error.

    Returns 0 on success, line number of first error on parse error (doesn't
    stop on first error), -1 on file open error.

  \param filename имя ini-файла
  \param handler функция-обработчик найденных значений
  \param user указатель на пользовательские данные
  \return В случае возникновения ошибки возвращается ее код. В случае успеха
   возвращается \ref ak_error_ok (ноль).                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_ini_parse( const char* filename, ini_handler handler, void* user )
{
  FILE *file = NULL;
  int error = ak_error_ok;

  if(( file = fopen(filename, "r")) == NULL ) return ak_error_message_fmt( ak_error_open_file,
                                                   __func__, "wrong opening a %s file", filename );
  error = ak_libakrypt_ini_parse_file( file, handler, user );
  fclose( file );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! An ini_reader function to read the next line from a string buffer. This
   is the fgets() equivalent used by ini_parse_string(). */
/* ----------------------------------------------------------------------------------------------- */
 static char* ini_reader_string(char* str, int num, void* stream) {
    ini_parse_string_ctx* ctx = (ini_parse_string_ctx*)stream;
    const char* ctx_ptr = ctx->ptr;
    size_t ctx_num_left = ctx->num_left;
    char* strp = str;
    char c;

    if (ctx_num_left == 0 || num < 2)
        return NULL;

    while (num > 1 && ctx_num_left != 0) {
        c = *ctx_ptr++;
        ctx_num_left--;
        *strp++ = c;
        if (c == '\n')
            break;
        num--;
    }

    *strp = '\0';
    ctx->ptr = ctx_ptr;
    ctx->num_left = ctx_num_left;
    return str;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Same as ini_parse(), but takes a zero-terminated string with the INI data
    instead of a file. Useful for parsing INI data from a network socket or
    already in memory.

  \param строка, содержащая данные в формате ini-файла
  \param handler функция-обработчик найденных значений
  \param user указатель на пользовательские данные
  \return В случае возникновения ошибки возвращается ее код. В случае успеха
   возвращается \ref ak_error_ok (ноль).                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_ini_parse_string( const char* string, ini_handler handler, void* user )
{
  ini_parse_string_ctx ctx;

  ctx.ptr = string;
  ctx.num_left = strlen(string);
 return ak_ini_parse_stream( (ini_reader)ini_reader_string, &ctx, handler, user );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_ini.c  */
/* ----------------------------------------------------------------------------------------------- */
