/* ----------------------------------------------------------------------------------------------- */
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 #define aktool_magic_number    (113)

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void );
 int aktool_key_new( void );
 int aktool_key_new_keypair( bool_t );
 int aktool_key_certificate( void );
 int aktool_key_print_disclaimer( void );
 int aktool_key_input_name( ak_handle );

/* ----------------------------------------------------------------------------------------------- */
 static struct key_info {
   char *algorithm;
   ak_handle key, vkey;
   char *key_description;
   export_format_t format;
   char *curve;
   size_t days;
   struct certificate_opts opts;
   char password[aktool_max_password_len];

   char ok_file[FILENAME_MAX]; /* сохраняем секретный ключ */
   char op_file[FILENAME_MAX];  /* сохраняем открытый ключ */
   char req_file[FILENAME_MAX];    /* читаем открытый ключ */
   char key_file[FILENAME_MAX];   /* читаем секретный ключ */
 } ki;


/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_print_disclaimer( void )
{
  printf(_(" -----\n"
   " You are about to be asked to enter information that will be incorporated\n"
   " into your secret key and certificate request.\n"
   " What you are about to enter is what is called a Distinguished Name or a DN.\n"
   " There are quite a few fields but you can leave some blank.\n"
   " For some fields there will be a default value.\n"
   " If you do not want to provide information just enter a string of one or more spaces.\n"
   " -----\n"));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void )
{
  printf(
   _("aktool key [options]  - key generation and management functions\n\n"
     //"usage for secret keys:\n"	   
     //"  aktool k -na hmac-streebog256 -ok hmac.key\n\n"
     //"usage for key pairs:\n"
     //"  aktool k -na sign256 -ok my.key --op my.request\n"
     //"  aktool k -na sign512 -ok ca.key --op ca.cer --to certificate\n\n"
     "available options:\n"
     " -a, --algorithm         specify the name of the cryptographic algorithm for the new key\n"
     "                         one can use any supported names or identifiers of algorithm\n"
     " -c, --cert              create a public key certificate from a given request\n"
     "     --curve             set the elliptic curve identifier for public keys\n"
     "     --days              set the days count to expiration date of secret or public key\n"
     "     --key               set the secret key to sign the public key certificate\n"
     " -l, --label             assign the user-defined label to secret key\n"
     " -n, --new               generate a new key or key pair for specified algorithm\n"
     "     --ok,               short form of --output-key option,\n"
     "     --output-key        set the file name for the new secret key\n"
     "     --op,               short form of --output-public-key option\n"
     "     --output-public-key set the file name for the new public key request\n"
     "     --password          specify the password for storing a secret key directly in command line\n"
     "     --req               set the name of request to certificate which would be signed\n"   
     "     --to                set the format of output file [ enabled values : der, pem, certificate ]\n\n"
     "options for customizing a public key's certificate:\n"
     "     --ca                use as certificate authority [ enabled values: true, false ]\n"
     "     --pathlen           set the maximal length of certificate's chain\n"
     "     --digitalSignature  use for verifying a digital signatures of user data\n"
     "     --contentCommitment \n"
     "     --keyEncipherment   use for encipherment of secret keys\n"
     "     --dataEncipherment  use for encipherment of user data (is not usally used)\n"
     "     --keyAgreement      use in key agreement protocols for subject's authentication\n"
     "     --keyCertSign       use for verifying of public key's certificates\n"
     "     --cRLSign           use for verifying of revocation lists of certificates\n"
    
  ));

 return aktool_print_common_options();
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   aktool_key.c  */
/* ----------------------------------------------------------------------------------------------- */
