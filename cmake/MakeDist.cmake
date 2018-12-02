# -------------------------------------------------------------------------------------------------- #
# генерация файла для сборки архива (только для UNIX)
set( MYDFILE "${CMAKE_BINARY_DIR}/make-dist-${FULL_VERSION}.sh" )

if( CMAKE_HOST_UNIX )
  file( WRITE ${MYDFILE} "#/bin/bash\n" )

  # создаем каталог и копируем файлы с исходными текстами
  file( APPEND ${MYDFILE} "mkdir -p libakrypt-${FULL_VERSION}/source\n")
  foreach( file ${HEADERS} ${SOURCES} ${MAIN_HEADER} )
    file( APPEND ${MYDFILE}
            "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}/source\n")
  endforeach()

  # создаем каталог examples и копируем файлы с примерами (неэкспортируемые + арифметика)
  file( APPEND ${MYDFILE} "mkdir -p libakrypt-${FULL_VERSION}/examples\n")
  foreach( file ${EXAMPLES_LIST} )
    file( APPEND ${MYDFILE}
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/examples/example-${file}.c libakrypt-${FULL_VERSION}/examples\n")
  endforeach()
  # создаем каталог tests и копируем файлы с тестами (неэкспортируемые функции + арифметика)
  file( APPEND ${MYDFILE} "mkdir -p libakrypt-${FULL_VERSION}/tests\n")
  foreach( file ${INTERNAL_TEST_LIST} )
    file( APPEND ${MYDFILE}
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/tests/test-${file}.c libakrypt-${FULL_VERSION}/tests\n")
  endforeach()
  foreach( file ${ARITHMETIC_TESTS_LIST} )
    file( APPEND ${MYDFILE}
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/tests/test-${file}.c libakrypt-${FULL_VERSION}/tests\n")
  endforeach()

#  # создаем каталог asn1 и копируем файлы с реализацией asn1
#  file( APPEND ${MYDFILE} "mkdir -p libakrypt-${FULL_VERSION}/asn1\n" )
#  foreach( file ${ASN1_HEADERS} ${ASN1_SOURCES} ${ASN1_FILES} )
#    file( APPEND ${MYDFILE}
#     "cp -fL --preserve=all ${file} libakrypt-${FULL_VERSION}/asn1\n")
#  endforeach()

  # создаем каталог doc и копируем файлы с документацией
  file( APPEND ${MYDFILE} "mkdir -p libakrypt-${FULL_VERSION}/doc\n" )
  foreach( file ${DOCS} )
    file( APPEND ${MYDFILE}
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}/doc\n")
  endforeach()

  # создаем каталог cmake и копируем файлы cmake
  file( APPEND ${MYDFILE} "mkdir -p libakrypt-${FULL_VERSION}/cmake\n" )
  foreach( file ${CMAKES} )
    file( APPEND ${MYDFILE}
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}/cmake\n")
  endforeach()

  # создаем каталог akrypt и копируем файлы с консольными утилитами
  file( APPEND ${MYDFILE} "mkdir -p libakrypt-${FULL_VERSION}/akrypt\n" )
  set( AKRYPT ${AKRYPT_SOURCES} ${AKRYPT_FILES} )
  foreach( file ${AKRYPT} )
    file( APPEND ${MYDFILE}
     "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}/akrypt\n")
  endforeach()

  # копируем оставшиеся файлы
  file( APPEND ${MYDFILE} "mkdir -p libakrypt-${FULL_VERSION}/cmake\n" )
  foreach( file ${OTHERS} )
    file( APPEND ${MYDFILE}
                "cp -fL --preserve=all ${CMAKE_SOURCE_DIR}/${file} libakrypt-${FULL_VERSION}\n")
  endforeach()

  # собираем дистрибутив
  file( APPEND ${MYDFILE} "tar -cjvf libakrypt-${FULL_VERSION}.tar.bz2 libakrypt-${FULL_VERSION}\n")
  file( APPEND ${MYDFILE} "rm -R libakrypt-${FULL_VERSION}\n")
  file( APPEND ${MYDFILE} "akrypt hash -r -o libakrypt-${FULL_VERSION}.streebog256 libakrypt-${FULL_VERSION}.tar.bz2\n")

  message("-- Creating a make-dist-${FULL_VERSION}.sh file - done ")
  execute_process( COMMAND chmod +x ${MYDFILE} )
  add_custom_target( dist ${MYDFILE} )
endif()

# -------------------------------------------------------------------------------------------------- #
