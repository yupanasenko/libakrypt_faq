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
/*   ak_keylist.h                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_KEYLIST_H__
#define    __AK_KEYLIST_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 struct keylist_node;
 typedef struct keylist_node *ak_keylist_node;

/* ----------------------------------------------------------------------------------------------- */
 int ak_keylist_create( void );
 int ak_keylist_destroy( void );
 ak_keylist_node ak_keylist_add_key( ak_pointer , 
                                          ak_oid_engine , ak_function_free_object *, const char * );
 ak_pointer ak_keylist_destroy_node( ak_keylist_node );
#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_keylist.h  */
/* ----------------------------------------------------------------------------------------------- */
