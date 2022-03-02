#pragma once
#include "AES.h"
#include "DES.h"
#include "STD_TYPES.h"
#include "stdio.h"
// generate a mac version of the message => using 3DES
void MAC(uint8* message, uint8* key, uint8 size);

// 1- determine the size of mac in the message
// 2- put the first n character from the mac 
//		at the end of the message
void combine_message(uint8* message, uint8* state, uint8* temp_mac_message, uint8 state_size, uint8 sizeOfMAC_in_message);

void separete_mac(uint8* message, uint8* data, uint8* mac, uint8 message_size, uint8 mac_size);

// used in the mac to generate the other 2 needed keys
void keyChange(uint8* key, uint8 value, uint8 keysize);

//	used in order to not destory the original message.
void copyArray(uint8* arrOriginal, uint8* arrCopy, uint8 size);

bool macCompare(uint8* data, uint8* mac, uint8* mac_key, uint8 data_size, uint8 mac_size);