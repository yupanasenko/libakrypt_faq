# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
if( CMAKE_HOST_UNIX )
  if( LIBAKRYPT_SHARED_LIB )
    install( TARGETS akrypt-shared
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
  endif()
  if( LIBAKRYPT_STATIC_LIB )
    install( TARGETS akrypt-static
             LIBRARY DESTINATION lib
             ARCHIVE DESTINATION lib
           )
  endif()
  install( CODE "execute_process( COMMAND strip -s akrypt${LIBAKRYPT_EXT} )" )
  install( TARGETS akrypt${LIBAKRYPT_EXT} RUNTIME DESTINATION bin )
#  install( FILES akrypt/akrypt.1 DESTINATION man/man1 )
  install( FILES ${MAIN_HEADER} DESTINATION include )
  install( FILES libakrypt.conf DESTINATION ${LIBAKRYPT_CONF} )

  find_file( AKRYPT_MSGFMT msgfmt )
  if( AKRYPT_MSGFMT )
    install( CODE "execute_process( COMMAND msgfmt ${CMAKE_SOURCE_DIR}/akrypt/akrypt.po -o ${CMAKE_BINARY_DIR}/akrypt.mo )" )
    install( FILES ${CMAKE_BINARY_DIR}/akrypt.mo DESTINATION /usr/share/locale/ru/LC_MESSAGES )
  endif()
endif()
# -------------------------------------------------------------------------------------------------- #
