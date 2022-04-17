# -------------------------------------------------------------------------------------------------- #
# Copyright (c) 2014 - 2022 by Axel Kenzo, axelkenzo@mail.ru
#
# MakeDoc.cmake
# -------------------------------------------------------------------------------------------------- #
find_program( GZIP gzip )
if( GZIP )
  message( "-- gzip found (${GZIP})" )
else()
  message( "-- gzip not found" )
endif()

find_program( SPHINX sphinx-build )
if( SPHINX )
  message( "-- sphinx-build found (${SPHINX})" )
else()
  message( "-- sphinx-build not found" )
endif()

find_program( QHELPGENERATOR qhelpgenerator )
if( QHELPGENERATOR )
  message( "-- qhelpgenerator found (${QHELPGENERATOR})" )
else()
  message( "-- qhelpgenerator not found" )
endif()

# -------------------------------------------------------------------------------------------------- #
if( SPHINX )
  configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/Makefile.in ${CMAKE_CURRENT_BINARY_DIR}/sphinx/Makefile @ONLY )

  set( script ${CMAKE_CURRENT_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )
  file( WRITE ${script} "#/bin/bash\n cd ${CMAKE_CURRENT_BINARY_DIR}/sphinx \n" )

 # строим красивый вывод в html
  file( APPEND ${script} "make html\n" )
 # формируем консольный мануал (в сжатом виде)
  file( APPEND ${script} "make man\n" )
  file( APPEND ${script} "cp ${CMAKE_CURRENT_BINARY_DIR}/sphinx/man/aktool.1 ${CMAKE_CURRENT_SOURCE_DIR}/aktool \n" )
 # формируем документацию в формате qthelp
  if( QHELPGENERATOR )
    file( APPEND ${script} "make qthelp\n" )
    file( APPEND ${script} "qcollectiongenerator qthelp/libakrypt.qhcp\n" )
  endif()
  file( APPEND ${script} "cd ${CMAKE_CURRENT_BINARY_DIR}\n" )

 # добавляем цель сборки
  execute_process( COMMAND chmod +x ${script} )
  add_custom_target( doc ${script} )
  message("-- Script for documentation is done (now \"make doc\" enabled)")

endif()

# -------------------------------------------------------------------------------------------------- #
#                                                                                     MakeDoc.cmake  #
# -------------------------------------------------------------------------------------------------- #


