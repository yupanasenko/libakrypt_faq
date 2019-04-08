/* Пример, иллюстрирующий процесс создания контекста защищенного соединения,
   а также его внутреннюю структуру.
   Внимание! Используются неэкспортируемые функции библиотеки и прямой доступ к полям
   контекста защищенного взаимодействия.

   test-internal-fiot-context01.c
*/
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ak_fiot.h>
 #include <ak_curves.h>

 int main( void )
{
  ssize_t len = 0;
  struct fiot actx;
  char message[160];
  role_t role = undefined_role;

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();
 /* устанавливаем максимальный уровень аудита */
  ak_log_set_level( fiot_log_maximum );

 /* инициализируем контекст и выводим информацию */
  printf("fiot context ");
  if( ak_fiot_context_create( &actx ) == ak_error_ok )
    printf("Ok [%u bytes]\n", (unsigned int) sizeof( struct fiot ));
   else goto lab_exit;

 /* слегка меняем длины внутренних буфферов */
  ak_fiot_context_set_frame_size( &actx, inframe, 2500 );
  printf("  in buffer: %u bytes\n",
    (unsigned int) ak_fiot_context_get_frame_size( &actx, inframe ));
  printf(" out buffer: %u bytes\n",
    (unsigned int) ak_fiot_context_get_frame_size( &actx, oframe ));

 /* устанавливаем и проверяем роль */
  ak_fiot_context_set_role( &actx, client_role );
  printf(" role: %d (", role = ak_fiot_context_get_role( &actx ));
   switch( role  ) {
    case client_role: printf("client)\n"); break;
    case server_role: printf("server)\n"); break;
    case undefined_role: printf("undefined)\n"); break;
  }
  printf(" state: %d\n", ak_fiot_context_get_state( &actx ));

 /* устанавливаем параметры эллиптической кривой */
  if( ak_fiot_context_set_curve( &actx, rfc4357_gost3410_2001_paramsetA ) == ak_error_ok )
    printf(" elliptic curve Ok\n");
   else goto lab_exit;

   /* для вывода знаечний используется прямой доступ к полям структуры */
    ak_mpzn_to_hexstr_static( actx.curve->a, actx.curve->size, message, sizeof( message ));
    printf(" a = %s\n", message );
    ak_mpzn_to_hexstr_static( actx.curve->b, actx.curve->size, message, sizeof( message ));
    printf(" b = %s\n", message );
    ak_mpzn_to_hexstr_static( actx.curve->p, actx.curve->size, message, sizeof( message ));
    printf(" p = %s\n", message );
    ak_mpzn_to_hexstr_static( actx.curve->q, actx.curve->size, message, sizeof( message ));
    printf(" q = %s\n", message );
    ak_mpzn_to_hexstr_static( actx.curve->point.x, actx.curve->size, message, sizeof( message ));
    printf("px = %s\n", message );
    ak_mpzn_to_hexstr_static( actx.curve->point.y, actx.curve->size, message, sizeof( message ));
    printf("py = %s\n", message );
    ak_mpzn_to_hexstr_static( actx.curve->point.z, actx.curve->size, message, sizeof( message ));
    printf("pz = %s\n", message );

 /* обрабатываем идентификаторы участников протокола */
  ak_fiot_context_set_user_identifier( &actx, server_role, "server number one\0x0", 18 );

  len = ak_fiot_context_get_user_identifier( &actx, server_role, message, sizeof( message ));
  printf("server id: %s (%d bytes)\n", message, (int) len );
  if( !ak_buffer_is_assigned( &actx.client_id )) printf("client id: [unassigned]\n");

 /* еще раз используем доступ ко внутренним полям контекста и получаем случайные данные */
  actx.plain_rnd.random( &actx.plain_rnd, message, 32 );
  printf("rnd: ");
   for( len = 0; len < 32; len++ ) printf("%02X", (ak_uint8)message[len] );
  printf(" (plain generator)\n");

 /* выводим текущие ограничения */
  printf("restrictions:\n");
  printf(" maxFrameLength %u\n", actx.restriction.maxFrameLength );
  printf(" maxFrameCount %u\n", actx.restriction.maxFrameCount );
  printf(" maxFrameKeysCount %u\n", actx.restriction.maxFrameKeysCount );
  printf(" maxApplicationSecretCount %u\n", actx.restriction.maxApplicationSecretCount );

  ak_fiot_context_destroy( &actx );
  lab_exit: ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
