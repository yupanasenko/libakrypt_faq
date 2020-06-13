# -------------------------------------------------------------------------------------------------- #
# генерация документации (только для UNIX)
# -------------------------------------------------------------------------------------------------- #
find_program( PANDOC pandoc )
find_program( SED sed )
find_program( DOXYGEN doxygen )
find_program( XELATEX xelatex )
find_program( QHELPGENERATOR qhelpgenerator )

set( script ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )

if( LIBAKRYPT_DOC )
  file( WRITE ${script} "#/bin/bash\n" )

  # документация для функций библиотеки
  if( DOXYGEN )
    # doxygen найден и документация может быть сгенерирована
    configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.in ${CMAKE_BINARY_DIR}/Doxyfile @ONLY )
    file( APPEND ${script} "doxygen Doxyfile\n" )

    if( QHELPGENERATOR )
      file( APPEND ${script} "cp doc/html/libakrypt.qch ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.qch\n" )
      file( APPEND ${script} "rm doc/html/libakrypt.qch\n" )
    endif()
    file( APPEND ${script} "tar -cjvf libakrypt-doc-${FULL_VERSION}.tar.bz2 doc/html\n")
  else()
    message("-- doxygen not found")
  endif()

  # документация для утилиты aktool
  if( LIBAKRYPT_AKTOOL )
   # подправляем исходники
    configure_file( ${CMAKE_SOURCE_DIR}/aktool/aktool.template.in ${CMAKE_BINARY_DIR}/aktool.template @ONLY )

    if( PANDOC )
      # определяем команду для генерации man файла
      file( APPEND ${script} "echo Documentation for aktool utility\n" )
      file( APPEND ${script}
        "pandoc -s -t man ${CMAKE_SOURCE_DIR}/aktool/Readme.md -o ${CMAKE_SOURCE_DIR}/aktool/aktool.1\n" )

      # определяем команду для генерации pdf файла
      if( XELATEX )
        file( APPEND ${script}
          "pandoc -s ${CMAKE_SOURCE_DIR}/aktool/Readme.md"
          " --pdf-engine=xelatex --template ${CMAKE_BINARY_DIR}/aktool.template"
          " -o ${CMAKE_BINARY_DIR}/aktool-doc-${FULL_VERSION}.pdf\n" )
      endif()
    endif()
  endif()

  execute_process( COMMAND chmod +x ${script} )
  add_custom_target( doc ${script} )
  message("-- Script for documentation is done (now \"make doc\" enabled)")
endif()

## -------------------------------------------------------------------------------------------------- #
## текущее состояние doxygen конфликтует с texlive, нужна пауза
#if( LIBAKRYPT_PDF_DOC )
# # подправляем исходники
#  configure_file( ${CMAKE_SOURCE_DIR}/doc/libakrypt-doc.tex.in
#                                                 ${CMAKE_BINARY_DIR}/latex/libakrypt-doc.tex @ONLY )
#  configure_file( ${CMAKE_SOURCE_DIR}/doc/Makefile.in ${CMAKE_BINARY_DIR}/latex/Makefile @ONLY )

# # копируем данные
#  foreach( file ${DOC_SOURCES} )
#    execute_process( COMMAND cp ${CMAKE_SOURCE_DIR}/doc/${file} ${CMAKE_BINARY_DIR}/latex/${file} )
#  endforeach()

# # формируем аннотацию
#  if( PANDOC )
#    execute_process( COMMAND pandoc -f markdown -t latex --top-level-division=chapter
#          -o ${CMAKE_BINARY_DIR}/latex/00-introduction.tex ${CMAKE_SOURCE_DIR}/doc/00-introduction.md )
#    execute_process( COMMAND pandoc -f markdown -t latex --top-level-division=chapter
#          -o ${CMAKE_BINARY_DIR}/latex/01-install-guide.tex ${CMAKE_SOURCE_DIR}/doc/01-install-guide.md )
#    execute_process( COMMAND pandoc -f markdown -t latex --top-level-division=chapter
#          -o ${CMAKE_BINARY_DIR}/latex/06-asn1.tex ${CMAKE_SOURCE_DIR}/doc/06-asn1.md )

#    if( SED )
#      execute_process( COMMAND sed -i s/chapter/chapter*/g ${CMAKE_BINARY_DIR}/latex/00-introduction.tex )
#      execute_process( COMMAND sed -i s/section/section*/g ${CMAKE_BINARY_DIR}/latex/00-introduction.tex )
#    endif()
#  endif()
##  # doxygen найден и документация может быть сгенерирована
##    set( LIBAKRYPT_PDF_HEADER "refman_header.tex" )
##    set( LIBAKRYPT_PDF_FOOTER "refman_footer.tex" )

##    configure_file( ${CMAKE_SOURCE_DIR}/doc/refman_header.in
##                                               ${CMAKE_BINARY_DIR}/refman_header.tex @ONLY )
##    configure_file( ${CMAKE_SOURCE_DIR}/doc/refman_footer.in
##                                               ${CMAKE_BINARY_DIR}/refman_footer.tex @ONLY )

##     if( PANDOC )
##       execute_process( COMMAND pandoc -f markdown -t latex --top-level-division=chapter -o ${CMAKE_BINARY_DIR}/readme.tex ${CMAKE_SOURCE_DIR}/Readme.md )
##       if( SED )
##         execute_process( COMMAND sed -i s/chapter/chapter*/g ${CMAKE_BINARY_DIR}/readme.tex )
##         execute_process( COMMAND sed -i s/section/section*/g ${CMAKE_BINARY_DIR}/readme.tex )
##       endif()
##       message("-- English documentation in latex format updated")
##     endif()

##  endif()
##endif()
