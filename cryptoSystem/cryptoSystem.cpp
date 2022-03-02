// cryptoSystem.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Crypto.h"
#include "STD_TYPES.h"
#include "STD_Print.h"


#define mac_size 3
using namespace std;
//unsigned char ciphertext[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
   //                              0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
int main()
{

    // sending side
    //the message will be 20 char
    unsigned char message[16];
    // unsigned char state[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    //                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    
    unsigned char state[] = {  0x00, 0x11, 0x22, 0x33,
                               0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb,
                               0xcc, 0x00, 0x00, 0x00};
    // generating key for the final AES
    unsigned char key_AES[] = { 0x00, 0x01, 0x02, 0x03,
                                0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b,
                                0x0c, 0x0d, 0x0e, 0x0f};
    // generating key for the MAC
    unsigned char key_MAC[] = { 0x00, 0x01, 0x02, 0x03,
                                0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b,
                                0x0c, 0x00, 0x00, 0x00 };
    //sent messgae
    printMessage(state, (uint8) sizeof(state), "sent message");
    
    //-----------------------------------------------//
    
    // get the MAC for authintication 
    unsigned char temp_mac_message [16];
    copyArray(state,temp_mac_message, (uint8)sizeof(state));
    MAC(temp_mac_message, key_MAC , (uint8)sizeof(state));
    
    printMessage(temp_mac_message, (uint8)sizeof(temp_mac_message),"encryption after mac");
    
    //-----------------------------------------------//
    //combine the state with the mac
    
    combine_message(message, state, temp_mac_message, (uint8)sizeof(state)-mac_size,mac_size);
    printMessage(message, (uint8)sizeof(message),"combining the message");
    
    //----------------------------------------------//
    
    //AES for the message for confidientiallyty 
    aes_enc_dec(message, key_AES, 0);
    printMessage(message, (uint8)sizeof(message), "AES enc Messgae ");
    //-----testing--------------------------//
    //uint8 AES_test_vector[] = { 0x69, 0xc4, 0xe0, 0xd8,
    //                            0x6a, 0x7b, 0x04, 0x30,
    //                            0xd8, 0xcd, 0xb7, 0x80,
    //                            0x70, 0xb4, 0xc5, 0x5a };
    //printMessage(AES_test_vector, 16, "testing vector :");

    //aes_enc_dec(AES_test_vector, key_AES, 0);
    //printMessage(AES_test_vector, (uint8)sizeof(AES_test_vector), "AES enc Messgae ");
    
    
    /*----------------------------------------------------------------------------------------*/
    // reciving side
    /*----------------------------------------------------------------------------------------*/
    uint8 REC_key_AES[] = { 0x00, 0x01, 0x02, 0x03,
                            0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b,
                            0x0c, 0x0d, 0x0e, 0x0f };

    uint8 REC_key_MAC[] = { 0x00, 0x01, 0x02, 0x03,
                            0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b,
                            0x0c, 0x00, 0x00, 0x00 };

    aes_enc_dec(message,REC_key_AES, 1);
    printMessage(message, (uint8)sizeof(message), "AES dec Messgae ");
    
    //decryption testing
    //aes_enc_dec(AES_test_vector, key_AES2, 1);
    //printMessage(AES_test_vector, (uint8)sizeof(AES_test_vector), "AES enc Messgae ");

    uint8 data[16];
    uint8 temp_data[16];
    uint8 mac[mac_size];
    // separate the mac from the message
    separete_mac(message, data, mac, (uint8)sizeof(message), mac_size);
    printMessage(data, 16, "display recieved data");
    printMessage(mac, mac_size, "display mac to check");

    //generate the mac from the message again
    copyArray(data, temp_data, (uint8)sizeof(data));
    
    // compare the mac 
    if (macCompare(temp_data, mac, REC_key_MAC, (uint8)sizeof(data), mac_size))
    {
        printf("message recieved successfully");
    }
}
/*
* des_ctx dc1; // Key schedule structure
unsigned char *cp;
unsigned char data[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8,
0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
unsigned char key[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
unsigned char key1[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xfe};
unsigned char key2[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xdc,0xfe};
cp = data;
///First 8 bytes of Data will be Encrypted then Decrypted
TripleDES_ENC( &dc, cp, 1, key, key1, key2); // 3DES Encrypt
TripleDES_DEC( &dc, cp, 1, key, key1, key2); // 3DES Decrypt
/// All 16 Bytes of Data will be Encrypted then Decrypted with CBC
TripleDES_ENC_CBC( &dc, cp, 2, key, key1, key2); // 3DES Encrypt
TripleDES_DEC_CBC( &dc, cp, 2, key, key1, key2); // 3DES Decrypt
*/