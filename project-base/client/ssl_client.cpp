//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries
#include <openssl/rand.h>	// Used for the random challenge

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client serveraddress:portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    
	//create the random number generator
	RAND_load_file("/dev/random", 128);

	unsigned char randNum[20];
	memset(randNum, 0, sizeof(randNum));
	int rtest = RAND_bytes(randNum, 20);
	
	if(rtest == 0)
	{
		printf("not enough random seed");
		exit(0);
	}

	//SSL_write
	//SSL_write(ssl, randomNumber.c_str(), strlen(randomNumber.c_str()));
	SSL_write(ssl, randNum, sizeof(randNum));
    
    printf("SUCCESS.\n");
	//printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str());
	printf("    (Challenge sent: \"%s\")\n", buff2hex((const unsigned char*)randNum, sizeof(randNum) ).c_str() );

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");

	int len = 0;
	char key_buf[1024];
	memset(key_buf, 0, sizeof(key_buf));

	//SSL_read;
	len = SSL_read(ssl, key_buf, 1024);

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)key_buf, len).c_str(), len);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");

	BIO *chal, *hash;

	//BIO_new(BIO_s_mem());
	//BIO_write
	chal = BIO_new(BIO_s_mem());
	BIO_puts(chal, (const char *)randNum);

	//BIO_new(BIO_f_md());
	hash = BIO_new(BIO_f_md());

	//BIO_set_md;
	BIO_set_md(hash, EVP_sha1());

	//BIO_push;
	BIO_push(hash, chal);

	//BIO_gets;

    int mdlen=0;

	//Get digest - generated key
	char hash_string[EVP_MAX_MD_SIZE];
	memset(hash_string, 0, sizeof(hash_string));
	mdlen = BIO_gets(hash, hash_string, EVP_MAX_MD_SIZE);

	unsigned char decrypt_key[mdlen];
	memset(decrypt_key, 0, sizeof(decrypt_key));

	//get encrypted message
	char pubKey[] = "rsapublickey.pem";

	BIO *publicKey;
	
	//BIO_new_file
	publicKey = BIO_new_file(pubKey, "r");

	//PEM_read_bio_RSA_PUBKEY
	RSA * rsa_public = PEM_read_bio_RSA_PUBKEY(publicKey, NULL, NULL, NULL);
	
	//RSA_public_decrypt
	RSA_public_decrypt(len, (unsigned char *)key_buf, decrypt_key, rsa_public, RSA_PKCS1_PADDING);

	string generated_key;
	string decrypted_key;

	generated_key.assign( buff2hex((const unsigned char*) hash_string, mdlen) );
	decrypted_key.assign( buff2hex((const unsigned char*) decrypt_key, mdlen) );

	//BIO_free
	BIO_free(hash);
    
	//printf("AUTHENTICATION\n");
	printf("\n      (Generated key: %s)\n", generated_key.c_str());
	printf("      (Decrypted key: %s)\n", decrypted_key.c_str());

	if(generated_key == decrypted_key)
		printf("    SERVER AUTHENTICATED\n");
	else
		printf("    SERVER NOT AUTHENTICATED\n");
	//printf("    (Generated key: %s)\n", generated_key.c_str());
	//printf("    (Decrypted key: %s)\n", decrypted_key.c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	PAUSE(2);
	//BIO_flush
    //BIO_puts
	//SSL_write
	SSL_write(ssl, filename, strlen(filename));

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...\nFile Contents:\n");


	//prepare file to write received file to
	char * outfilename = "ReceivedFile.txt";

	BIO *boutfile;
	boutfile = BIO_new_file(outfilename, "w");

	char fbuf[1024];
    memset(fbuf,0,sizeof(fbuf));

	int declen=0;
    unsigned char decr[1024];
	memset(decr, 0, sizeof(decr));

	int rLen, wLen;

	//recieve the file
	while( (rLen = SSL_read(ssl, fbuf, 1024)) >= 1)
	{
		//RSA_public_decrypt
		//RSA_public_decrypt(rLen, (unsigned char *)fbuf, decr, rsa_public, RSA_PKCS1_PADDING);

		//wLen = BIO_write(boutfile, decr, rLen);
		wLen = BIO_write(boutfile, fbuf, rLen);
		printf("%s", decr);

		BIO_flush(boutfile);
	}

	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//SSL_shutdown
	SSL_shutdown(ssl);
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
