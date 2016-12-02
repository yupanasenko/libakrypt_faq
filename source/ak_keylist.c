/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2016 by Axel Kenzo, axelkenzo@mail.ru                                           */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*   Redistribution and use in source and binary forms, with or without modification, are          */
/*   permitted provided that the following conditions are met:                                     */
/*                                                                                                 */
/*   1. Redistributions of source code must retain the above copyright notice, this list of        */
/*      conditions and the following disclaimer.                                                   */
/*   2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/*      conditions and the following disclaimer in the documentation and/or other materials        */
/*      provided with the distribution.                                                            */
/*   3. Neither the name of the copyright holder nor the names of its contributors may be used     */
/*      to endorse or promote products derived from this software without specific prior written   */
/*      permission.                                                                                */
/*                                                                                                 */
/*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/*   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/*   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL        */
/*   THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, */
/*   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/*   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/*   AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/*   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/*   OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/*                                                                                                 */
/*   ak_keylist.c                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_random.h>
 #include <ak_keylist.h>
 #include <ak_skey.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс состояний элемента ключевого списка */
 typedef enum {
  /*! \brief элемент не определен */
   node_undefined,
  /*! \brief элемент только создан/считан из хранилища */
   node_created,
  /*! \brief элемент изменен в процессе работы*/
   node_modified,
  /*! \brief элемент в текущем статусе сохранен в хранилище */
   node_saved
} ak_keylist_node_status;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура элемента ключевого списка */
 struct keylist_node
{
 /*! \brief указатель на ключ */
 ak_pointer keyptr;
 /*! \brief тип ключа */
 ak_oid_engine engine;
 /*! \brief пользовательское описание */
 ak_buffer description;
 /*! \brief функция удаления и очистки памяти из под ключа */
 ak_function_free_object *free;
 /*! \brief указатель на другой элемент списка */
 ak_keylist_node next;
 /*! \brief идентификатор ключа */
 ak_key keyID;
 /*! \brief статус ключа */
 ak_keylist_node_status status;
};

/* ----------------------------------------------------------------------------------------------- */
 struct {
 /*! \brief указатели на первый и последний элемент списка */
 ak_keylist_node last;
 /*! \brief генератор ключевых значений */
 ak_random generator;
 /*! \brief начальное значение для ключевых идентификаторов */
 ak_key currentID;
} global_keylist;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Мьютекс для блокировки массива ключей при добавлении новых значений */
 static pthread_mutex_t ak_keylist_add_key_mutex = PTHREAD_MUTEX_INITIALIZER;
/*! \brief Мьютекс для блокировки массива ключей при поиске ключевых значений */
 static pthread_mutex_t ak_keylist_find_key_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ----------------------------------------------------------------------------------------------- */
 int ak_keylist_create( void )
{
  int error = ak_error_ok;
  global_keylist.last = NULL;
 #ifdef __linux__ 
  if(( global_keylist.generator = ak_random_new_file("/dev/random")) == NULL ) {
 #else
  if(( global_keylist.generator = ak_random_new_lcg()) == NULL ) {
 #endif
    error = ak_error_get_value();
    ak_error_message( error, "wrong initialization of random generator", __func__ );
  }
  if(( global_keylist.currentID = ( ak_key )ak_random_value()) == 0 ) global_keylist.currentID++;
 return error;
} 

/* ----------------------------------------------------------------------------------------------- */
 ak_keylist_node ak_keylist_add_key( ak_pointer key,
                        ak_oid_engine engine, ak_function_free_object *ffree, const char *message )
{
  ak_keylist_node node = NULL;
  /* сначала заполняем структуру данными */
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to key", __func__ );
    return NULL;
  }
  if( ffree == NULL ) {
    ak_error_message( ak_error_undefined_function, "using an undefined free function", __func__ );
    return NULL;
  }
  if(( node = malloc( sizeof( struct keylist_node ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong creation of keylist node", __func__ );
    return NULL;
  }
  node->keyptr = key;
  node->engine = engine;
  node->description = ak_buffer_new_str( message );
  node->status = node_created;
  node->free = ffree;
  node->next = NULL;

  /* потом вставляем структуру в список */
  pthread_mutex_lock( &ak_keylist_add_key_mutex );
  if( global_keylist.currentID == 0 ) global_keylist.currentID = 1;
  node->keyID = ++global_keylist.currentID;
  if( global_keylist.last == NULL ) global_keylist.last = node;
  else {
         node->next = global_keylist.last;
         global_keylist.last = node;
       }
  pthread_mutex_unlock( &ak_keylist_add_key_mutex );
 return node;
} 

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_keylist_destroy_node( ak_keylist_node node )
{
  if( node == NULL ) {
    ak_error_message( ak_error_null_pointer, "destroying a null pointer to keylist node", __func__ );
    return NULL;
  }
  if( node->free == NULL ) {
    ak_error_message( ak_error_undefined_function,
                                  "destroying a node with null pointer to free function", __func__ );
  } else node->keyptr = node->free( node->keyptr );

  node->free = NULL;
  node->engine = undefined_engine;
  node->keyID = 0;
  node->description = ak_buffer_delete( node->description );
  node->status = node_undefined;
  node->next = NULL;
  free( node );
 return NULL; 
} 

/* ----------------------------------------------------------------------------------------------- */
 int ak_keylist_destroy( void )
{
 /* удаляем генератор */
  if( global_keylist.generator != NULL ) 
                          global_keylist.generator = ak_random_delete( global_keylist.generator );
 /* удаляем список ключей */
  while( global_keylist.last != NULL ) {
    ak_keylist_node node = global_keylist.last;
    global_keylist.last = node->next;
    node = ak_keylist_destroy_node( node );
  }
 return ak_error_ok; 
} 

/* ----------------------------------------------------------------------------------------------- */
 ak_keylist_node ak_keylist_find_node( ak_key id )
{
  ak_keylist_node node = NULL;

  pthread_mutex_lock( &ak_keylist_find_key_mutex );
  if( global_keylist.last == NULL ) {
    pthread_mutex_unlock( &ak_keylist_find_key_mutex );
    ak_error_message( ak_error_zero_length, "wrong finding a key in zero list", __func__ );
    return NULL; 
  }

  node = global_keylist.last;
  while( node != NULL ) {
     if( node->keyID == id ) break;
      else node = node->next;
  }
  pthread_mutex_unlock( &ak_keylist_find_key_mutex );
  if( node == NULL )
    ak_error_message( ak_error_find_pointer, "wrong search a secret key", __func__ );
  else ak_error_set_value( ak_error_ok );
 return node;
} 

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_key_get_description( ak_key id )
{
 const char *string = NULL;
 ak_keylist_node node = ak_keylist_find_node(id);
 if( node == NULL ) {
   ak_error_message( ak_error_get_value(), "wrong search a secret key", __func__ );
   return ak_null_string;
 }
 string = ak_buffer_get_str( node->description );
 if( string == NULL ) return ak_null_string;
  else return string;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_key_get_number( ak_key id )
{
  ak_keylist_node node = ak_keylist_find_node(id);
  if( node == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong search a secret key", __func__ );
    return ak_null_string;
  }
  if( node->engine == block_cipher )
    return ak_buffer_get_str(((ak_cipher_key)node->keyptr)->key->number);
  ak_error_message( ak_error_oid_engine, "using a key with undefined engine", __func__ );
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_uint32 ak_key_get_resource( ak_key id )
{
 ak_keylist_node node = ak_keylist_find_node(id);
 if( node == NULL ) {
   ak_error_message( ak_error_get_value(), "wrong search a secret key", __func__ );
   return ak_false;
 }
 if( node->engine != block_cipher ) {
   ak_error_message( ak_error_oid_engine, "using a non block cipher key", __func__ );
   return ak_false;
 }
 return ((ak_cipher_key) node->keyptr)->resource;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_key ak_key_new_magma( const char *message )
{
  ak_cipher_key ckey = NULL;
  ak_keylist_node node = NULL; 

  if(( ckey = ak_cipher_key_new_magma_random( NULL, global_keylist.generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong new key creation", __func__ );
    return 0; 
  }
  if(( node = ak_keylist_add_key( ckey, block_cipher, ak_cipher_key_delete, message )) == NULL ) {
    int error = ak_error_get_value();
    ak_error_message( error, "wrong creation of new key node", __func__ );
    ckey = ak_cipher_key_delete( ckey );
    return error;
  }
  return node->keyID;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_key ak_key_new_magma_oid( ak_oid oid, const char *message )
{
  ak_cipher_key ckey = NULL;
  ak_keylist_node node = NULL; 

  if(( ckey = ak_cipher_key_new_magma_random( oid, global_keylist.generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong new key creation", __func__ );
    return 0; 
  }
  if(( node = ak_keylist_add_key( ckey, block_cipher, ak_cipher_key_delete, message )) == NULL ) {
    int error = ak_error_get_value();
    ak_error_message( error, "wrong creation of new key node", __func__ );
    ckey = ak_cipher_key_delete( ckey );
    return error;
  }
  return node->keyID;
} 

/* ----------------------------------------------------------------------------------------------- */
 ak_key ak_key_new_kuznetchik( const char *message )
{
  ak_cipher_key ckey = NULL;
  ak_keylist_node node = NULL; 

  if(( ckey = ak_cipher_key_new_kuznetchik_random( global_keylist.generator )) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong new key creation", __func__ );
    return 0; 
  }
  if(( node = ak_keylist_add_key( ckey, block_cipher, ak_cipher_key_delete, message )) == NULL ) {
    int error = ak_error_get_value();
    ak_error_message( error, "wrong creation of new key node", __func__ );
    ckey = ak_cipher_key_delete( ckey );
    return error;
  }
  return node->keyID;
} 

/* ----------------------------------------------------------------------------------------------- */
 int ak_key_encrypt_ecb( ak_key kid, ak_pointer in, ak_pointer out, size_t size )
{
  int error = ak_error_ok;	
  ak_keylist_node node = NULL;

  if(( node = ak_keylist_find_node( kid )) == NULL ) {
    error = ak_error_get_value();
    ak_error_message( error, "wrong finding a secret key with given ID", __func__ );
    return error;
  }
  if( node->engine != block_cipher ) {
    ak_error_message( ak_error_oid_engine, "using a non block cipher key", __func__ );
    return ak_error_oid_engine;
  }
  error = ak_cipher_key_encrypt_ecb( (ak_cipher_key) node->keyptr, in, out, size );
  node->status = node_modified;
 return error;
} 

/* ----------------------------------------------------------------------------------------------- */
 int ak_key_decrypt_ecb( ak_key kid, ak_pointer in, ak_pointer out, size_t size )
{
  int error = ak_error_ok;	
  ak_keylist_node node = NULL;
  
  if(( node = ak_keylist_find_node( kid )) == NULL ) {
    error = ak_error_get_value();
    ak_error_message( error, "wrong finding a secret key with given ID", __func__ );
    return error;
  }
  if( node->engine != block_cipher ) {
    ak_error_message( ak_error_oid_engine, "using a non block cipher key", __func__ );
    return ak_error_oid_engine;
  }
  error = ak_cipher_key_decrypt_ecb( (ak_cipher_key) node->keyptr, in, out, size );
  node->status = node_modified;
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_keylist.c  */
/* ----------------------------------------------------------------------------------------------- */
