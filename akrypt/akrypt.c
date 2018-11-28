/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>
 #include <ak_tools.h>
 #include <ak_hash.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef _WIN32
 #include <tchar.h>
 #include <strsafe.h>
 int main( int argc, TCHAR *argv[] )
#else
 int main( int argc, char *argv[] )
#endif
{
     WIN32_FIND_DATA ffd;
     LARGE_INTEGER filesize;
     TCHAR szDir[MAX_PATH];
     size_t length_of_arg;
     HANDLE hFind = INVALID_HANDLE_VALUE;
     DWORD dwError=0;

     int i = 0, error;
     struct file fp;
     struct hash ctx;
     ak_uint8 out[32];

     SetConsoleCP( 1251 );
     SetConsoleOutputCP( 1251 );

     _tprintf(TEXT("\nœ–»¬≈“!!!\n\n"), argv[1]);


     ak_libakrypt_create( NULL );


     // If the directory is not specified as a command-line argument,
     // print usage.

     if(argc != 2)
     {
        _tprintf(TEXT("\nUsage: %s <directory name>\n"), argv[0]);
        return (-1);
     }

     // Check that the input path plus 3 is not longer than MAX_PATH.
     // Three characters are for the "\*" plus NULL appended below.

     StringCchLength(argv[1], MAX_PATH, &length_of_arg);

     if (length_of_arg > (MAX_PATH - 3))
     {
        _tprintf(TEXT("\nDirectory path is too long.\n"));
        return (-1);
     }

     _tprintf(TEXT("\nTarget directory is %s\n\n"), argv[1]);

     // Prepare string for use with FindFile functions.  First, copy the
     // string to a buffer, then append '\*' to the directory name.

     StringCchCopy(szDir, MAX_PATH, argv[1]);
     StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

     // Find the first file in the directory.

     hFind = FindFirstFile(szDir, &ffd);

     if (INVALID_HANDLE_VALUE == hFind)
     {
        // DisplayErrorBox(TEXT("FindFirstFile"));
        printf("ERROR\n");
        return dwError;
     }

     // List all the files in the directory with some info about them.

     do
     {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
           _tprintf(TEXT("  %s   <DIR>\n"), ffd.cFileName );
           //printf(TEXT("  %s   <DIR>\n"), ffd.cFileName );
        }
        else
        {
           filesize.LowPart = ffd.nFileSizeLow;
           filesize.HighPart = ffd.nFileSizeHigh;
           _tprintf(TEXT("  %s   %ld bytes -> "), ffd.cFileName, filesize.QuadPart);
           //printf(TEXT("  %s   %ld bytes -> "), ffd.cFileName, filesize.QuadPart);

           printf("%s\n", ffd.cFileName );

           /* ‰Ó·‡‚ÎˇÂÏ ı˝¯ */
           printf("open file: %d\n", error = ak_file_open_to_read( &fp, ffd.cFileName ));
           if( error == ak_error_ok ) {

           printf("close file: %d\n", ak_file_close( &fp ));


           printf("create ctx: %d\n",
                  ak_hash_context_create_streebog256( &ctx ));
           printf("hash file (address): %p\n",
                  (void *) ak_hash_context_file( &ctx, ffd.cFileName, out ));
           if( ak_error_get_value() == ak_error_ok ) {
               for( i = 0; i < 32; i++ ) printf("%02X", out[i] );
               printf("\n");
           } ak_error_set_value( ak_error_ok );
           printf("destroy: %d\n", ak_hash_context_destroy( &ctx ));
           /* ------------- */

           }
        }
     }
     while (FindNextFile(hFind, &ffd) != 0);

     dwError = GetLastError();
     if (dwError != ERROR_NO_MORE_FILES)
     {
        //DisplayErrorBox(TEXT("FindFirstFile"));
        printf("ERROR\n");
     }

     FindClose(hFind);


     ak_libakrypt_destroy();


     return dwError;

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       akrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
