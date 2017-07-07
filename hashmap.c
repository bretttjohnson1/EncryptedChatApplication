/*
Brett Johnson
btj12
hashmap.c
2/27/2016
This file manages all hasmap related functions. The project uses it to achieve O(n) runtime on the -t and -m options
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "bool.h"
#include "hashmap.h"

hashmap * hash_setup(uint32_t length){
	node *hashlist;
	hashlist = malloc(sizeof(node)*length);
   if(hashlist == NULL)
      return NULL;
	for(uint32_t i = 0; i<length; i++) {
		hashlist[i].isfull = false;
		hashlist[i].haschild = false;
	}
	hashmap* map = malloc(sizeof(hashmap));
	map->hashmap_pointer = hashlist;
	map->length = length;
	return map;
}
//checks if keys are equal
bool hash_equals(unsigned char *string1,unsigned char *string2,int len1,int len2){
	if(len1 != len2) return false;
	for(int i = 0; i<len1; i++) {
		if(string1[i]!=string2[i]) return false;
	}
	return true;
}

bool hash_add(hashmap map,void *keydata,int keydatalen,void *valdata,int valdatalen){
	node * hashlist = map.hashmap_pointer;
	uint32_t hashval = hash_func(keydata,keydatalen,map.length);
	if(hashlist[hashval].isfull) {
      //the node is full so a collision occured
      //iterates until it finds an empty bucket given a collision
      //it also checks for duplicates and returns false if detected
      node *currentnode = hashlist+hashval;
      if(hash_equals(currentnode->keydata,(unsigned char*) keydata,currentnode->keydatalen,keydatalen)) {
         return false;
      }
		while(currentnode->haschild) {
			currentnode = currentnode->next;
         if(hash_equals(currentnode->keydata,(unsigned char*) keydata,currentnode->keydatalen,keydatalen)) {
   			return false;
   		}
		}
      //fill the next node
		currentnode->next = malloc(sizeof(node));
		currentnode->next->keydatalen = keydatalen;
		currentnode->next->keydata = malloc(keydatalen);
		currentnode->next->valdatalen = valdatalen;
		currentnode->next->valdata = malloc(valdatalen);
		currentnode->haschild = true;
		currentnode->next->isfull = true;
      unsigned char * nodekeydata = currentnode->next->keydata;
		for(int i = 0; i<keydatalen; i++) {
			nodekeydata[i] = ((unsigned char *)keydata)[i];
		}
      unsigned char * nodevaldata = currentnode->next->valdata;
		for(int i = 0; i<valdatalen; i++) {
			nodevaldata[i] = ((unsigned char *)valdata)[i];
		}
	}else{
      //no collison means just fill the given node
		hashlist[hashval].isfull = true;
		hashlist[hashval].keydata  = malloc(keydatalen);
		hashlist[hashval].keydatalen = keydatalen;
      unsigned char * nodekeydata = hashlist[hashval].keydata;
		for(int i = 0; i<keydatalen; i++) {
			nodekeydata[i] = ((unsigned char *)keydata)[i];
		}
		hashlist[hashval].valdatalen = valdatalen;
		hashlist[hashval].valdata = malloc(valdatalen);
      unsigned char * nodevaldata = hashlist[hashval].valdata;
		for(int i = 0; i<valdatalen; i++) {
			nodevaldata[i] = ((unsigned char *)valdata)[i];
		}
	}
	return true;
}

//chose 5 so the number is multiplied by 32 and then subtracted to make 31
//31 is a prime number and easy to compute
//this is an implementation of the java hashfuction
const int shift_to_multiply_by_32 = 5;
uint32_t hash_func(void *keydata,int keydatalen,int length){
	uint64_t hashval = 0;
	for(int i = 0; i<keydatalen; i++) {
		hashval = (hashval<<shift_to_multiply_by_32)-hashval+((unsigned char *)keydata)[i];
	}
	return hashval%length;
}

//iterate through and close buckets
void rec_close(node *currentnode){
	if(currentnode->haschild) {
		rec_close(currentnode->next);
	}
   free(currentnode->keydata);
   free(currentnode->valdata);
	free(currentnode);
}

//deletes a map when done
void hash_close(hashmap *map){
	for(uint32_t i = 0; i<map->length; i++) {
      node * currentnode = map->hashmap_pointer+i;
		if(currentnode->haschild)
			rec_close(currentnode->next);
	}
	free(map->hashmap_pointer);
	free(map);
}

//gets a value from the hashmap and returns the node
void * hash_get(hashmap map,void *keydata,int keydatalen){
	node * hashlist = map.hashmap_pointer;
	uint32_t hashval = hash_func(keydata,keydatalen,map.length);
	if(hashlist[hashval].isfull) {
		if(hash_equals(hashlist[hashval].keydata,(unsigned char*) keydata,hashlist[hashval].keydatalen,keydatalen)) {
			return (hashlist+hashval)->valdata;
		}
		node *currentnode = hashlist+hashval;
		while(currentnode->isfull) {
			if(hash_equals(currentnode->keydata,(unsigned char*) keydata,currentnode->keydatalen,keydatalen)) {
				return currentnode->valdata;
			}
			if(currentnode->haschild) {
				currentnode = currentnode->next;
			}else{
				break;
			}
		}
	}
	return NULL;
}

//sets existing value in the hashmap
//returns false if does not exist
bool hash_set(hashmap map,void *keydata,int keydatalen,void *valdata,int valdatalen){
	node * hashlist = map.hashmap_pointer;
	uint32_t hashval = hash_func(keydata,keydatalen,map.length);
	if(hashlist[hashval].isfull) {
		if(hash_equals(hashlist[hashval].keydata,(unsigned char*) keydata,hashlist[hashval].keydatalen,keydatalen)) {
			hashlist[hashval].valdatalen = valdatalen;
         free(hashlist[hashval].valdata);
			hashlist[hashval].valdata = malloc(valdatalen);
         unsigned char * nodevaldata = hashlist[hashval].valdata;
			for(int i = 0; i<valdatalen; i++) {
				nodevaldata[i] = ((unsigned char *)valdata)[i];
			}
			return true;
		}
		node *currentnode = hashlist+hashval;
		while(currentnode->isfull) {
			if(hash_equals(currentnode->keydata,(unsigned char*) keydata,currentnode->keydatalen,keydatalen)) {
				currentnode->valdatalen = valdatalen;
            free(currentnode->valdata);
				currentnode->valdata = malloc(valdatalen);
            unsigned char * nodevaldata = currentnode->valdata;
				for(int i = 0; i<valdatalen; i++) {
					nodevaldata[i] = ((unsigned char *)valdata)[i];
				}
				return true;
			}
			if(currentnode->haschild) {
				currentnode = currentnode->next;
			}else{
				break;
			}
		}
	}
	return false;
}

bool hash_contains(hashmap map,void *keydata,int keydatalen){
   node * hashlist = map.hashmap_pointer;
	uint32_t hashval = hash_func(keydata,keydatalen,map.length);
	if(hashlist[hashval].isfull) {
		if(hash_equals(hashlist[hashval].keydata,(unsigned char*) keydata,hashlist[hashval].keydatalen,keydatalen)) {
			return true;
		}
		node *currentnode = hashlist+hashval;
		while(currentnode->isfull) {
			if(hash_equals(currentnode->keydata,(unsigned char*) keydata,currentnode->keydatalen,keydatalen)) {
				return true;
			}
			if(currentnode->haschild) {
				currentnode = currentnode->next;
			}else{
				break;
			}
		}
	}
	return false;
}

void hash_remove(hashmap map,void *keydata,int keydatalen){
   node * hashlist = map.hashmap_pointer;
	uint32_t hashval = hash_func(keydata,keydatalen,map.length);

	if(hashlist[hashval].isfull) {
      node *currentnode = hashlist+hashval;
		while(currentnode->isfull) {
			if(hash_equals(currentnode->keydata,(unsigned char*) keydata,currentnode->keydatalen,keydatalen)) {
            if(currentnode->haschild) {
               free(currentnode->keydata);
               currentnode->keydata = currentnode->next->keydata;
               currentnode->keydatalen = currentnode->next->keydatalen;
               free(currentnode->valdata);
               currentnode->valdata = currentnode->next->valdata;
               currentnode->valdatalen = currentnode->next->valdatalen;
               currentnode->haschild = currentnode->next->haschild;
            }else{
               currentnode->isfull=false;
            }
            return;
			}
			if(currentnode->haschild) {
				currentnode = currentnode->next;
			}else{
				break;
			}
		}
	}
	return;
}
