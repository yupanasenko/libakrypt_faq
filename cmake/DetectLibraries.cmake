# -------------------------------------------------------------------------------------------------- #
if( MSVC )

  # в начале ищем библиотеки, если нет - выходим
  find_library( PTHREAD pthreadVC2 )
  if( PTHREAD )
    message("-- Searching pthreadVC2 - done ")
    set( LIBAKRYPT_LIBS pthreadVC2 )

    # потом ищем заголовочный файл, если нет - выходим
    find_file( PTHREAD_H pthread.h )
    if( PTHREAD_H )
      # устанавливаем флаг
      set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_PTHREAD" )

      # наконец, проверяем, определена ли структура timespec
      check_c_source_compiles("
         #include <pthread.h>
          int main( void ) {
          return 0;
         }" LIBAKRYPT_HAVE_STRUCT_TIMESPEC )
      if( LIBAKRYPT_HAVE_STRUCT_TIMESPEC )
      else()
        set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_STRUCT_TIMESPEC" )
      endif()

    else()
      message("-- pthread.h not found")
    endif()
  else()
    message("-- pthreadVC2 not found")
  endif()
else()
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_PTHREAD" )
endif()

# -------------------------------------------------------------------------------------------------- #
# вырабатываем и подключаем файл с ресурсами библиотеки
if( WIN32 )
  configure_file( ${CMAKE_SOURCE_DIR}/libakrypt.rc.in ${CMAKE_SOURCE_DIR}/libakrypt.rc @ONLY )
  set( SOURCES ${SOURCES} libakrypt.rc )
  set( CMAKE_BUILD_TYPE "Release" )
endif()


# -------------------------------------------------------------------------------------------------- #
# теперь поиск gmp
if( LIBAKRYPT_GMP_TESTS )

  find_library( LIBGMP gmp )
  if( LIBGMP )
    find_file( LIBGMP_H gmp.h )
    if( LIBGMP_H )
      # теперь готовим тесты для GMP
       set( LIBAKRYPT_LIBS ${LIBAKRYPT_LIBS} gmp )
       set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBAKRYPT_HAVE_GMP_H" )

    else()
       message("-- gmp.h not found")
       exit()
    endif()
  else()
    message("-- libgmp not found")
    exit()
  endif()
endif()
