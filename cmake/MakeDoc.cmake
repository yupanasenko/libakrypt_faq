# -------------------------------------------------------------------------------------------------- #
# генерация документации (только для UNIX)
# -------------------------------------------------------------------------------------------------- #
find_program( PANDOC pandoc )
if( PANDOC )
  message( "-- pandoc found (${PANDOC})" )
else()
  message( "-- pandoc not found" )
endif()

find_program( SED sed )
if( SED )
  message( "-- sed found (${SED})" )
else()
  message( "-- sed not found" )
endif()

find_program( DOXYGEN doxygen )
if( DOXYGEN )
  message( "-- doxygen found (${DOXYGEN})" )
else()
  message( "-- doxygen not found" )
endif()

find_program( XELATEX xelatex )
if( XELATEX )
  message( "-- xelatex found (${XELATEX}" )
else()
  message( "-- xelateX not found" )
endif()

find_program( QHELPGENERATOR qhelpgenerator )
if( QHELPGENERATOR )
  message( "-- qhelpgenerator found (${QHELPGENERATOR})" )
else()
  message( "-- qhelpgenerator not found" )
endif()

find_program( ETAGS etags )
if( ETAGS )
  message( "-- etags found (${ETAGS})" )
else()
  message( "-- etags not found" )
endif()

find_program( GZIP gzip )
if( GZIP )
  message( "-- gzip found (${GZIP})" )
else()
  message( "-- gzip not found" )
endif()

find_program( XGETTEXT xgettext )
if( XGETTEXT )
  message( "-- xgettext found (${XGETTEXT})" )
else()
  message( "-- xgettext not found" )
endif()

# -----------------------------------------------------------------------------------
configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/aktool/aktool.1.in ${CMAKE_CURRENT_BINARY_DIR}/aktool.1 @ONLY )

# -----------------------------------------------------------------------------------
# скрипты для генерации документации
if( UNIX )
  set( script ${CMAKE_CURRENT_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )
  set( pdf-script ${CMAKE_CURRENT_BINARY_DIR}/make-pdfdoc-${FULL_VERSION}.sh )
  file( WRITE ${script} "#/bin/bash\n" )

# -----------------------------------------------------------------------------------
# определяем команду для генерации man файла
  if( PANDOC )
    execute_process( COMMAND pandoc -f man -t latex ${CMAKE_CURRENT_BINARY_DIR}/aktool.1 -s -o ${CMAKE_CURRENT_BINARY_DIR}/aktool.tex --template ${CMAKE_CURRENT_SOURCE_DIR}/doc/aktool-header.tex )
  endif()
  message("-- Manual documentation for aktool utility created" )

# -----------------------------------------------------------------------------------
# документация для функций библиотеки
  if( DOXYGEN )
    # doxygen найден и документация может быть сгенерирована
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.akbase.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.akbase @ONLY )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/libakbase-header.tex.in ${CMAKE_CURRENT_BINARY_DIR}/libakbase-header.tex @ONLY )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.akrypt.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.akrypt @ONLY )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/doc/libakrypt-header.tex.in ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-header.tex @ONLY )

    file( APPEND ${script} "doxygen Doxyfile.akbase\n" )
    file( APPEND ${script} "doxygen Doxyfile.akrypt\n" )

    # добавляем генерацию мануалов
    if( XELATEX )
      file( WRITE ${pdf-script} "#/bin/bash\n" )
      file( APPEND ${pdf-script} "${script}\n" )
      if( PANDOC )
        file( APPEND ${pdf-script} "xelatex -interaction=nonstopmode ${CMAKE_CURRENT_BINARY_DIR}/aktool.tex\n" )
        file( APPEND ${pdf-script} "mv ${CMAKE_CURRENT_BINARY_DIR}/aktool.pdf ${CMAKE_CURRENT_BINARY_DIR}/aktool-doc-${FULL_VERSION}.pdf\n" )
      endif()
      file( APPEND ${pdf-script} "cd doc-akbase/latex; make; cd ../..\n" )
      file( APPEND ${pdf-script} "cp doc-akbase/latex/refman.pdf ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-base-doc-${FULL_VERSION}.pdf\n")
      file( APPEND ${pdf-script} "cd doc-akrypt/latex; make; cd ../..\n" )
      file( APPEND ${pdf-script} "cp doc-akrypt/latex/refman.pdf ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.pdf\n")      
    endif()

    if( QHELPGENERATOR )
      file( APPEND ${script} "cp doc-akbase/html/akbase-library.qch ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-base-doc-${FULL_VERSION}.qch\n" )
      file( APPEND ${script} "rm doc-akbase/html/akbase-library.qch\n" )
      file( APPEND ${script} "cp doc-akrypt/html/akrypt-library.qch ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.qch\n" )
      file( APPEND ${script} "rm doc-akrypt/html/akrypt-library.qch\n" )
    endif()

    file( APPEND ${script} "tar -cjvf libakrypt-base-doc-${FULL_VERSION}.tar.bz2 doc-akbase/html\n")
    file( APPEND ${script} "tar -cjvf libakrypt-doc-${FULL_VERSION}.tar.bz2 doc-akrypt/html\n")
  endif()

# -----------------------------------------------------------------------------------
# добавляем поддержку etags
  file( APPEND ${script} "cd ${CMAKE_CURRENT_SOURCE_DIR}\n" )
  if( ETAGS )
    file( APPEND ${script} "cd ${CMAKE_CURRENT_SOURCE_DIR}; etags.emacs source/*.[ch]; cd ${CMAKE_CURRENT_BINARY_DIR}\n" )
  endif()

# -----------------------------------------------------------------------------------
  file( APPEND ${script} "cd ${CMAKE_CURRENT_BINARY_DIR}\n" )
  execute_process( COMMAND chmod +x ${script} )
  add_custom_target( doc ${script} )
  message("-- Script for documentation is done (now \"make doc\" enabled)")

  if( XELATEX )
    execute_process( COMMAND chmod +x ${pdf-script} )
    add_custom_target( pdf ${pdf-script} )
    message("-- Script for PDF documentation (using XeLaTeX engine) is done (now \"make pdf\" enabled)")
  endif()

# конец if( UNIX )
endif()

# -----------------------------------------------------------------------------------
# исполняем хвосты, т.е. то что почти забыли сделать
if( GZIP )
  execute_process( COMMAND  gzip --force ${CMAKE_CURRENT_BINARY_DIR}/aktool.1 )
endif()

# -----------------------------------------------------------------------------------
if( ETAGS )
  add_custom_target( tags COMMAND etags --recurse=yes --totals=yes -f ${CMAKE_CURRENT_SOURCE_DIR}/TAGS ${CMAKE_CURRENT_SOURCE_DIR} )
  message("-- Script for etags enabled (now \"make tags\" enabled)")
endif()

