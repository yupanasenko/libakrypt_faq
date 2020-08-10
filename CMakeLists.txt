# -------------------------------------------------------------------------------------------------- #
# Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru
#
# CMakeLists.txt
# -------------------------------------------------------------------------------------------------- #
cmake_minimum_required( VERSION 2.8 FATAL_ERROR )

# -------------------------------------------------------------------------------------------------- #
set( HEAD_VERSION 0 )
set( MAIN_VERSION 8 )
set( MINOR_VERSION 6 )
set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )

# -------------------------------------------------------------------------------------------------- #
# Формируем название проекта
project( libakrypt-${FULL_VERSION} C )

# -------------------------------------------------------------------------------------------------- #
# Перечень доступных опций для сборки библиотеки
option( AK_STATIC_LIB "Build the static library" ON )
option( AK_SHARED_LIB "Build the shared library" ON )

# -------------------------------------------------------------------------------------------------- #
# подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectHeaders )
include( DetectIntrinsics )

# -------------------------------------------------------------------------------------------------- #
# вырабатываем заголовочный файл
configure_file( ${CMAKE_SOURCE_DIR}/source/libakbase.h.in ${CMAKE_SOURCE_DIR}/source/libakbase.h @ONLY )
message("-- Generation of libakbase.h is done")

# -------------------------------------------------------------------------------------------------- #
# Определяем базовое множество исходных текстов библиотеки
set( MAIN_HEADERS source/libakbase.h )
set( AKBASE_SOURCES
  source/ak_tools.c
  source/ak_list.c
  source/ak_ini.c
  source/ak_file.c
)

# -------------------------------------------------------------------------------------------------- #
# Определем процедуры сборки библиотек - статической или динамической
include_directories( "source" )
if( AK_SHARED_LIB )
  add_library( akbase-shared SHARED ${MAIN_HEADERS} ${AKBASE_SOURCES} )
  set_target_properties( akbase-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  set_target_properties( akbase-shared PROPERTIES OUTPUT_NAME akbase CLEAN_DIRECT_CUSTOM 1 )
  message( "-- Building a shared library" )
endif()
#
if( AK_STATIC_LIB )
  add_library( akbase-static STATIC ${MAIN_HEADERS} ${AKBASE_SOURCES} )
  set_target_properties( akbase-static PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  set_target_properties( akbase-static PROPERTIES OUTPUT_NAME akbase CLEAN_DIRECT_CUSTOM 1 )
  message( "-- Building a static library" )
endif()

# -------------------------------------------------------------------------------------------------- #
# Сборка примеров, иллюстрирующих работу с внешним интерфейсом библиотеки
# -------------------------------------------------------------------------------------------------- #
set( EXAMPLES_LIST
  log
  ini
  file
)

foreach( programm ${EXAMPLES_LIST} )
  if( AK_STATIC_LIB )
    add_executable( example-${programm} examples/example-${programm}.c )
    target_link_libraries( example-${programm} akbase-static )
  else()
    if( AK_SHARED_LIB )
      add_executable( example-shared-${programm} examples/example-${programm}.c )
      target_link_libraries( example-shared-${programm} akbase-shared )
    endif()
  endif()
endforeach()

# -------------------------------------------------------------------------------------------------- #
# Сборка документации и завершающие настройки
 include( MakeDoc )

# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
if( CMAKE_HOST_UNIX )
  if( AK_STATIC_LIB )
    install( TARGETS akbase-static
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
  endif()
  if( AK_SHARED_LIB )
    install( TARGETS akbase-shared
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
  endif()
  install( FILES ${MAIN_HEADERS} DESTINATION include )
endif()

# -------------------------------------------------------------------------------------------------- #
#                                                                                    CMakeLists.txt
# -------------------------------------------------------------------------------------------------- #
