 #include <ak_hash.h>
 #include <ak_curves.h>
 #include <ak_parameters.h>
 #include <ak_mac.h>


 int main( void )
{
 char *str = NULL;
 struct hash hctx;
 ak_uint8 epsk[32];
 ak_uint8 rnd[32] = { 0xAF, 0x56, 0x19, 0x8E, 0x2A, 0xA4, 0x12, 0x45, 0x97, 0x74, 0x8D, 0xB8, 0x38,
                      0x29, 0x89, 0x60, 0x3D, 0x44, 0xD7, 0xB7, 0x82, 0x24, 0xD0, 0xF1, 0x54, 0xC6,
                      0x22, 0xC3, 0x2C, 0x85, 0x83, 0x1E };
 ak_uint8 kc8[32] = { 0x71, 0xDA, 0x7A, 0xF3, 0x39, 0x1C, 0x1C, 0xEF, 0x06, 0x3F, 0xCB, 0x3F, 0x8C,
                      0x96, 0xF7, 0x4C, 0x68, 0x94, 0xE0, 0x7E, 0xE9, 0x85, 0x51, 0xFC, 0xC9, 0x59,
                      0x64, 0x68, 0xF3, 0x58, 0x43, 0xA6 };
 ak_uint8 ks8[32] = { 0x95, 0xDE, 0xC4, 0xE0, 0xAF, 0x18, 0x9B, 0x94, 0xD9, 0xED, 0xC0, 0xFA, 0x91,
                      0x5C, 0x2F, 0xEA, 0xC2, 0x02, 0x32, 0xB6, 0x86, 0xD9, 0x22, 0xF0, 0xE5, 0xFC,
                      0x25, 0x29, 0x93, 0x60, 0xF0, 0xAF };

 ak_uint8 idepsk[9] = { 0x31, 0x32, 0x37, 0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x31 };
 ak_uint8 frame[160] =
  { 0xA0, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x70, 0x30, 0x20, 0xB0, 0xB1, 0x09 };

 struct wpoint pc;

 ak_libakrypt_create( NULL );

 /* генерим ePSK */
  ak_hash_create_streebog256( &hctx );
  ak_hash_context_ptr( &hctx, idepsk, sizeof( idepsk ), epsk );
  printf("epsk: %s\n", str = ak_ptr_to_hexstr( epsk, sizeof( epsk ), ak_false )); free(str);

 /* формируем точку кривой */
  ak_wpoint_pow( &pc, (ak_wpoint) &id_rfc4357_gost3410_2001_paramsetA.point, (ak_uint64 *)kc8,
                                ak_mpzn256_size, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA );
  ak_wpoint_reduce( &pc, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA );

  printf("Pc.x: %s\n", str = ak_ptr_to_hexstr( pc.x, 32, ak_false )); free( str );
  printf("Pc.y: %s\n", str = ak_ptr_to_hexstr( pc.y, 32, ak_false )); free( str );
  printf("Pc.z: %s\n", str = ak_ptr_to_hexstr( pc.z, 32, ak_false )); free( str );

 /* формирование фрейма */
  memcpy( frame+16, idepsk, 9 );
  memcpy( frame+25, rnd, 32 );
  frame[57] = 0x05;
  memcpy( frame+58, pc.x, 32 );
  memcpy( frame+90, pc.y, 32 );
  frame[122] = 0x00;

  frame[123] = 0x24; /* дополнение */
  frame[124] = 0x64;
  frame[125] = 0x55;

 /* формируем контрольную сумму */
  frame[126] = 0xB1;
  frame[127] = 0x20; /* 32 */

 /* вычисляем контрольную сумму */
  struct mac mctx;
  ak_mac_create_hmac_streebog256( &mctx );
  ak_mac_context_set_ptr( &mctx, epsk, sizeof( epsk ));
  ak_mac_context_ptr( &mctx, frame, 126, frame+128 );
  ak_mac_destroy( &mctx );

  printf("frame: %s\n", str = ak_ptr_to_hexstr( frame, sizeof( frame ), ak_false )); free( str );
  printf("frame: A000A000000000001100703020B0B1093132372E302E302E31AF56198E2AA4124597748DB8382989603D44D7B78224D0F154C622C32C85831E05DE277EB89968BBC60B3854283F855B028B2BDD781A9C3839FC41AD8B8EA32AF243CA69DCF666C981AD1D7861639A22B20358F4209A588D2CC94FA2F464FA1ACB00246455B12062FD7DC1BF74221682393EC5DF66605B4111212647E7B5EE092E7A23F759E0C4\n");


 /* формируем вторую точку */
  ak_wpoint_pow( &pc, (ak_wpoint) &id_rfc4357_gost3410_2001_paramsetA.point, (ak_uint64 *)ks8,
                                ak_mpzn256_size, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA );
  ak_wpoint_reduce( &pc, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA );

  printf("Ps.x: %s\n", str = ak_ptr_to_hexstr( pc.x, 32, ak_false )); free( str );
  printf("Ps.y: %s\n", str = ak_ptr_to_hexstr( pc.y, 32, ak_false )); free( str );
  printf("Ps.z: %s\n", str = ak_ptr_to_hexstr( pc.z, 32, ak_false )); free( str );

 ak_libakrypt_destroy();

}
