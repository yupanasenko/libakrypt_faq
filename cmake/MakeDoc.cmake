# -------------------------------------------------------------------------------------------------- #
# генерация файла для сборки документации (только для UNIX)
if( LIBAKRYPT_PDF_DOC )
  set( LIBAKRYPT_HTML_DOC ON )
endif()

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
if( LIBAKRYPT_PDF_DOC )
  find_file( XELATEX_BIN xelatex )
  if( XELATEX_BIN )
  # latex найден и pdf может быть сгенерирован корректно
     configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.in ${CMAKE_BINARY_DIR}/Doxyfile @ONLY )
#     configure_file( ${CMAKE_SOURCE_DIR}/doc/refman_header.in
#                                                ${CMAKE_BINARY_DIR}/refman_header.tex @ONLY )
#     configure_file( ${CMAKE_SOURCE_DIR}/doc/refman_footer.in
#                                                ${CMAKE_BINARY_DIR}/refman_footer.tex @ONLY )

     file( WRITE ${CMAKE_BINARY_DIR}/make-pdf-${FULL_VERSION}.sh "#/bin/bash\n" )
     file( APPEND ${CMAKE_BINARY_DIR}/make-pdf-${FULL_VERSION}.sh "doxygen Doxyfile\n" )
     file( APPEND ${CMAKE_BINARY_DIR}/make-pdf-${FULL_VERSION}.sh "cd doc/latex\n" )
     file( APPEND ${CMAKE_BINARY_DIR}/make-pdf-${FULL_VERSION}.sh "make\n" )
     file( APPEND ${CMAKE_BINARY_DIR}/make-pdf-${FULL_VERSION}.sh
               "cp refman.pdf ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.pdf\n" )
     file( APPEND ${CMAKE_BINARY_DIR}/make-pdf-${FULL_VERSION}.sh "cd ../..\n" )
     execute_process( COMMAND chmod +x ${CMAKE_BINARY_DIR}/make-pdf-${FULL_VERSION}.sh )
     add_custom_target( pdf ${CMAKE_BINARY_DIR}/make-pdf-${FULL_VERSION}.sh )
     message("-- Script for documentation in pdf format is done (now \"make pdf\" enabled)")

  else()
    message("-- xelatex not found")
    exit()
  endif()
endif()

# -------------------------------------------------------------------------------------------------- #
