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
  install( FILES akrypt/akrypt.1 DESTINATION man/man1 )
  install( FILES ${MAIN_HEADER} DESTINATION include )
  install( FILES libakrypt.conf DESTINATION ${LIBAKRYPT_CONF} )
endif()

# -------------------------------------------------------------------------------------------------- #
