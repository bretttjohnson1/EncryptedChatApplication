/*
Brett Johnson
btj12
hashmap.h
2/27/2016
this is the header file to hashmap.c. it holds the struct for the hasmap and the method declarations
*/
#include <stdint.h>
#include "bool.h"
#ifndef hashmap_header_file
#define hashmap_header_file

typedef struct Bucket node;
struct Bucket{
   bool isfull;
   bool haschild;
   unsigned char *keydata;
   int keydatalen;
   unsigned char *valdata;
   int valdatalen;
   node *next;
};
typedef struct hashmap hashmap;
struct hashmap{
   uint32_t length;
   node* hashmap_pointer;
};

hashmap *hash_setup(uint32_t length);
bool hash_equals(unsigned char *string1,unsigned char *string2,int len1,int len2);
bool hash_add(hashmap map,void *keydata,int keydatalen,void *valdata,int valdatalen);
void * hash_get(hashmap map,void *keydata,int keydatalen);
bool hash_set(hashmap map,void *keydata,int keydatalen,void *valdata,int valdatalen);
uint32_t hash_func(void *keydata,int keydatalen, int list_size);
bool hash_contains(hashmap map,void *keydata,int keydatalen);
void hash_remove(hashmap map,void *keydata,int keydatalen);
void hash_close(hashmap *map);

#endif
