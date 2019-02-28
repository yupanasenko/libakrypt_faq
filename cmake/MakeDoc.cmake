# -------------------------------------------------------------------------------------------------- #
# генерация файла для сборки документации (только для UNIX)
# -------------------------------------------------------------------------------------------------- #
if( LIBAKRYPT_HTML_DOC )
  find_file( DOXYGEN_BIN doxygen )
  if( DOXYGEN_BIN )
  # doxygen найден и документация может быть сгенерирована
     configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.in ${CMAKE_BINARY_DIR}/Doxyfile @ONLY )
     file( WRITE ${CMAKE_BINARY_DIR}/make-html-${FULL_VERSION}.sh "#/bin/bash\n" )
     file( APPEND ${CMAKE_BINARY_DIR}/make-html-${FULL_VERSION}.sh "doxygen Doxyfile\n" )
     file( APPEND ${CMAKE_BINARY_DIR}/make-html-${FULL_VERSION}.sh
                         "tar -cjvf libakrypt-doc-${FULL_VERSION}.tar.bz2 doc/html\n")

     find_file( QHELPGENERATOR_BIN qhelpgenerator )
     if( QHELPGENERATOR_BIN )
       file( APPEND ${CMAKE_BINARY_DIR}/make-html-${FULL_VERSION}.sh
          "cp doc/html/libakrypt.qch ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.qch\n" )
       file( APPEND ${CMAKE_BINARY_DIR}/make-html-${FULL_VERSION}.sh
                                                                "rm doc/html/libakrypt.qch\n" )
     endif()
     execute_process( COMMAND chmod +x ${CMAKE_BINARY_DIR}/make-html-${FULL_VERSION}.sh )
     add_custom_target( html ${CMAKE_BINARY_DIR}/make-html-${FULL_VERSION}.sh )
     message("-- Script for documentation in html format is done (now \"make html\" enabled)")

  else()
    message("-- doxygen not found")
    exit()
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
