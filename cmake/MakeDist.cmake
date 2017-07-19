# -------------------------------------------------------------------------------------------------- #
# генерация файла для сборки архива (только для UNIX)
if( CMAKE_HOST_UNIX )
  file( WRITE ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh "#/bin/bash\n" )

  # создаем каталог и копируем файлы с исходными текстами
  file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh "mkdir -p libakrypt-${FULL_VERSION}/source\n")
  foreach( file ${HEADERS} ${SOURCES} ${MAIN_HEADER} )
    file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
            "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}/source\n")
  endforeach()

  # создаем каталог examples и копируем файлы с примерами (обычные + неэкспортируемые + арифметика)
  file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh "mkdir -p libakrypt-${FULL_VERSION}/examples\n")
  foreach( file ${EXAMPLES_LIST} )
    file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/examples/example-${file}.c libakrypt-${FULL_VERSION}/examples\n")
  endforeach()
  foreach( file ${INTERNAL_EXAMPLES_LIST} )
    file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/examples/example-${file}.c libakrypt-${FULL_VERSION}/examples\n")
  endforeach()
  foreach( file ${ARITHMETIC_TESTS_LIST} )
    file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/examples/example-${file}.c libakrypt-${FULL_VERSION}/examples\n")
  endforeach()

  # создаем каталог doc и копируем файлы с документацией
  file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh "mkdir -p libakrypt-${FULL_VERSION}/doc\n" )
  foreach( file ${DOCS} )
    file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}/doc\n")
  endforeach()

  # создаем каталог cmake и копируем файлы cmake
  file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh "mkdir -p libakrypt-${FULL_VERSION}/cmake\n" )
  foreach( file ${CMAKES} )
    file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}/cmake\n")
  endforeach()

  # создаем каталог akrypt и копируем файлы с консольными утилитами
  file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh "mkdir -p libakrypt-${FULL_VERSION}/akrypt\n" )
  set( AKRYPT ${AKRYPT_SOURCES} ${AKRYPT_FILES} )
  foreach( file ${AKRYPT} )
    file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}/akrypt\n")
  endforeach()

  # копируем оставшиеся файлы
  file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh "mkdir -p libakrypt-${FULL_VERSION}/cmake\n" )
  foreach( file ${OTHERS} )
    file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
                "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}\n")
  endforeach()

  # собираем дистрибутив
  file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh
                      "tar -cjvf libakrypt-${FULL_VERSION}.tar.bz2 libakrypt-${FULL_VERSION}\n")
  file( APPEND ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh "rm -R libakrypt-${FULL_VERSION}\n")
  message("-- Creating a make-dist-${FULL_VERSION}.sh file - done ")
  execute_process( COMMAND chmod +x ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh )
  add_custom_target( dist ${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh )
endif()

# -------------------------------------------------------------------------------------------------- #
