# -------------------------------------------------------------------------------------------------- #
if( MSVC )
  
  # в начале ищем библиотеки, если нет - выходим
  find_library( PTHREAD pthreadVC2 )
  if( PTHREAD )
    message("-- Searching pthreadVC2 - done ")
    set( LIBAKRYPT_LIBS pthreadVC2 )
    
    # потом ищем заголовочный файл, если нет - выходим
    find_file( PTHREAD_H )
    if( PTHREAD_H )
    
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
      exit()
    endif()
  else()
    message("-- pthreadVC2 not found")
    exit()
  endif()
endif()
    
# вырабатываем и подключаем файл с ресурсами библиотеки    
if( WIN32 )
  configure_file( ${CMAKE_SOURCE_DIR}/libakrypt.rc.in ${CMAKE_SOURCE_DIR}/libakrypt.rc @ONLY )
  set( SOURCES ${SOURCES} libakrypt.rc )
  set( CMAKE_BUILD_TYPE "Release" )
endif()
