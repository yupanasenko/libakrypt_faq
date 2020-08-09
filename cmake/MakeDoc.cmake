# -------------------------------------------------------------------------------------------------- #
# генерация документации (только для UNIX)
# -------------------------------------------------------------------------------------------------- #
find_program( PANDOC pandoc )
find_program( SED sed )
find_program( DOXYGEN doxygen )
find_program( XELATEX xelatex )
find_program( QHELPGENERATOR qhelpgenerator )
find_program( ETAGS etags )

if( UNIX )
  set( script ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )
  file( WRITE ${script} "#/bin/bash\n" )
  
  # документация для функций библиотеки
  if( DOXYGEN )
    # doxygen найден и документация может быть сгенерирована
    configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.akbase.in ${CMAKE_BINARY_DIR}/Doxyfile.akbase @ONLY )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/libakbase-header.tex.in ${CMAKE_BINARY_DIR}/libakbase-header.tex @ONLY )

    file( APPEND ${script} "doxygen Doxyfile.akbase\n" )
    if( XELATEX )
      file( APPEND ${script} "cd doc-akbase/latex; make; cd ../..\n" )
      file( APPEND ${script} "cp doc-akbase/latex/refman.pdf ${CMAKE_BINARY_DIR}/akbase-library-doc-${FULL_VERSION}.pdf\n")
    endif()
    if( QHELPGENERATOR )
      file( APPEND ${script} "cp doc-akbase/html/akbase-library.qch ${CMAKE_BINARY_DIR}/akbase-library-doc-${FULL_VERSION}.qch\n" )
      file( APPEND ${script} "rm doc-akbase/html/akbase-library.qch\n" )
    endif()
    file( APPEND ${script} "tar -cjvf akbase-library-doc-${FULL_VERSION}.tar.bz2 doc-akbase/html\n")
  else()
      message("-- doxygen not found")
  endif()

  if( ETAGS )
    file( APPEND ${script} "cd ${CMAKE_SOURCE_DIR}; etags.emacs source/*.[ch]; cd ${CMAKE_BINARY_DIR}\n" )
  endif()

  execute_process( COMMAND chmod +x ${script} )
  add_custom_target( doc ${script} )
  message("-- Script for documentation is done (now \"make doc\" enabled)")
endif()
