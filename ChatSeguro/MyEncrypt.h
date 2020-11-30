#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

/*Create RSA structue to pass inside 'RSA_private_encrypt' API method*/
RSA * createRSA(unsigned char * key,int isPublic);

/*Function to perform encryption on data*/
int public_decrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);

int private_encrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);

/*Function to print previous error returned by the API method if any error caused*/
void printLastError(char *msg);

char* getKey(char *filename);

