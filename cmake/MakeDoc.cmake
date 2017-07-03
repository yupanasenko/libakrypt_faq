# -------------------------------------------------------------------------------------------------- #
# генерация файла для сборки документации (только для UNIX)
if( CMAKE_HOST_UNIX )
    set( LIBAKRYPT_PDF_HEADER "refman_header.tex" )
    set( LIBAKRYPT_PDF_FOOTER "refman_footer.tex" )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/refman_header.in
                                               ${CMAKE_BINARY_DIR}/refman_header.tex @ONLY )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/refman_footer.in
                                               ${CMAKE_BINARY_DIR}/refman_footer.tex @ONLY )

    message("-- Creating a fine view for documentation in pdf file - done ")
    configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.in ${CMAKE_BINARY_DIR}/Doxyfile @ONLY )
    file( WRITE ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh "#/bin/bash\n" )
    file( APPEND ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh "doxygen Doxyfile\n" )

   # получаем документацию в формате  PDF
    file( APPEND ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh "cd doc/latex\n" )
    file( APPEND ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh "make\n" )
    file( APPEND ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh
             "cp refman.pdf ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.pdf\n" )
    file( APPEND ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh "cd ../..\n" )

   # получаем документацию в формате QCH
    file( APPEND ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh
      "cp doc/html/libakrypt.qch ${CMAKE_BINARY_DIR}/libakrypt-${FULL_VERSION}.qch\n" )
    file( APPEND ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh
                                                        "rm doc/html/libakrypt.qch\n" )
   # получаем архив с html
    file( APPEND ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh
                         "tar -cjvf libakrypt-html-${FULL_VERSION}.tar.bz2 doc/html\n")
    message("-- Creating a make-doc-${FULL_VERSION}.sh file - done ")
    execute_process( COMMAND chmod +x ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )
    add_custom_target( doc ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )
endif()

# -------------------------------------------------------------------------------------------------- #
