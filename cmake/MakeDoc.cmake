# -------------------------------------------------------------------------------------------------- #
# генерация документации (только для UNIX)
# -------------------------------------------------------------------------------------------------- #
find_program( PANDOC pandoc )
if( PANDOC )
  message( "-- pandoc found" )
else()
  message( "-- pandoc not found" )
endif()

find_program( SED sed )
if( SED )
  message( "-- sed found" )
else()
  message( "-- sed not found" )
endif()

find_program( DOXYGEN doxygen )
if( DOXYGEN )
  message( "-- doxygen found" )
else()
  message( "-- doxygen not found" )
endif()

find_program( XELATEX xelatex )
if( XELATEX )
  message( "-- xelatex found" )
else()
  message( "-- xelateX not found" )
endif()

find_program( QHELPGENERATOR qhelpgenerator )
if( QHELPGENERATOR )
  message( "-- qhelpgenerator found" )
else()
  message( "-- qhelpgenerator not found" )
endif()

find_program( ETAGS etags )
if( ETAGS )
  message( "-- etags found" )
else()
  message( "-- etags not found" )
endif()

find_program( GZIP gzip )
if( GZIP )
  message( "-- gzip found" )
else()
  message( "-- gzip not found" )
endif()

find_program( XGETTEXT xgettext )
if( XGETTEXT )
  message( "-- xgettext found" )
else()
  message( "-- xgettext not found" )
endif()

# -----------------------------------------------------------------------------------
# скрипты для генерации документации
if( UNIX )

  set( script ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )
  set( pdf-script ${CMAKE_BINARY_DIR}/make-pdfdoc-${FULL_VERSION}.sh )
  file( WRITE ${script} "#/bin/bash\n" )

# -----------------------------------------------------------------------------------
# определяем команду для генерации man файла
  if( PANDOC )
    set( AKTOOL_DATE "18 июля 2021" )
    set( AKTOOL_FOOTER "Правила пользования" )
    execute_process( COMMAND pandoc --metadata=date:${AKTOOL_DATE} --metadata=title:aktool --metadata=section:1 --metadata=footer:${AKTOOL_FOOTER} -s -t man ${CMAKE_SOURCE_DIR}/aktool/Readme.md -o ${CMAKE_BINARY_DIR}/aktool.1 )
    if( GZIP )
      execute_process( COMMAND  gzip --force ${CMAKE_BINARY_DIR}/aktool.1 )
    endif()
    message("-- Manual documentation for aktool utility created" )
  endif()

# -----------------------------------------------------------------------------------
# документация для функций библиотеки
  if( DOXYGEN )
    # doxygen найден и документация может быть сгенерирована
    configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.akbase.in ${CMAKE_BINARY_DIR}/Doxyfile.akbase @ONLY )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/libakbase-header.tex.in ${CMAKE_BINARY_DIR}/libakbase-header.tex @ONLY )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.akrypt.in ${CMAKE_BINARY_DIR}/Doxyfile.akrypt @ONLY )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/libakrypt-header.tex.in ${CMAKE_BINARY_DIR}/libakrypt-header.tex @ONLY )

    file( APPEND ${script} "doxygen Doxyfile.akbase\n" )
    file( APPEND ${script} "doxygen Doxyfile.akrypt\n" )

    # добавляем генерацию мануалов
    if( PANDOC )
      file( APPEND ${script}
        "pandoc --metadata=date:\"${AKTOOL_DATE}\" --metadata=title:aktool --metadata=section:1 --metadata=footer:\"${AKTOOL_FOOTER}\" -s -t man ${CMAKE_SOURCE_DIR}/aktool/Readme.md -o ${CMAKE_BINARY_DIR}/aktool.1\n" )
      if( GZIP )
        file( APPEND ${script} "gzip --force ${CMAKE_BINARY_DIR}/aktool.1\n" )
      endif()
    endif()

    if( XELATEX )
      file( WRITE ${pdf-script} "#/bin/bash\n" )
      file( APPEND ${pdf-script} "${script}\n" )
      file( APPEND ${pdf-script} "cd doc-akbase/latex; make; cd ../..\n" )
      file( APPEND ${pdf-script} "cp doc-akbase/latex/refman.pdf ${CMAKE_BINARY_DIR}/libakrypt-base-doc-${FULL_VERSION}.pdf\n")
      file( APPEND ${pdf-script} "cd doc-akrypt/latex; make; cd ../..\n" )
      file( APPEND ${pdf-script} "cp doc-akrypt/latex/refman.pdf ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.pdf\n")
    endif()

    if( QHELPGENERATOR )
      file( APPEND ${script} "cp doc-akbase/html/akbase-library.qch ${CMAKE_BINARY_DIR}/libakrypt-base-doc-${FULL_VERSION}.qch\n" )
      file( APPEND ${script} "rm doc-akbase/html/akbase-library.qch\n" )
      file( APPEND ${script} "cp doc-akrypt/html/akrypt-library.qch ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.qch\n" )
      file( APPEND ${script} "rm doc-akrypt/html/akrypt-library.qch\n" )
    endif()

    file( APPEND ${script} "tar -cjvf libakrypt-base-doc-${FULL_VERSION}.tar.bz2 doc-akbase/html\n")
    file( APPEND ${script} "tar -cjvf libakrypt-doc-${FULL_VERSION}.tar.bz2 doc-akrypt/html\n")
  endif()

# -----------------------------------------------------------------------------------
# добавляем поддержку etags
  file( APPEND ${script} "cd ${CMAKE_SOURCE_DIR}\n" )
  if( ETAGS )
    file( APPEND ${script} "etags.emacs source/*.[ch]\n" )
  endif()

# -----------------------------------------------------------------------------------
# Формируем уточненный файл перевода (нужно, в основном, при разработке)
  if( GETTEXT_FOUND )
    find_program( XGETTEXT xgettext )
    if( XGETTEXT )
      file( APPEND ${script} "cd aktool\n" )
      file( APPEND ${script} "${XGETTEXT} aktool*.c -a -j --from-code utf-8 -o aktool.po\n" )
    endif()
  endif()

  file( APPEND ${script} "cd ${CMAKE_BINARY_DIR}\n" )
  execute_process( COMMAND chmod +x ${script} )
  add_custom_target( doc ${script} )
  message("-- Script for documentation is done (now \"make doc\" enabled)")

  if( XELATEX )
    execute_process( COMMAND chmod +x ${pdf-script} )
    add_custom_target( pdf ${pdf-script} )
    message("-- Script for PDF documentation (using xeLaTeX engine) is done (now \"make pdf\" enabled)")
  endif()

# -----------------------------------------------------------------------------------
# конец if( UNIX )
endif()

