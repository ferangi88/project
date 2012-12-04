//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");

    //SSL_read
	int buf_len = 0;
	char challenge_buf[1024];
	memset(challenge_buf, 0, sizeof(challenge_buf));

	buf_len = SSL_read(ssl, challenge_buf, 1024);

	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", buff2hex((const unsigned char*) challenge_buf, buf_len).c_str() );

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");

	BIO *chal, *hash;

	//BIO_new(BIO_s_mem());
	//BIO_write
	chal = BIO_new(BIO_s_mem());
	BIO_puts(chal, challenge_buf);

	//BIO_new(BIO_f_md());
	hash = BIO_new(BIO_f_md());

	//BIO_set_md;
	BIO_set_md(hash, EVP_sha1());

	//BIO_push;
	BIO_push(hash, chal);

	//BIO_gets;

    int mdlen=0;

	//Get digest
	char hash_string[EVP_MAX_MD_SIZE];
	memset(hash_string, 0, sizeof(hash_string));
	mdlen = BIO_gets(hash, hash_string, EVP_MAX_MD_SIZE);

	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*) hash_string, mdlen).c_str(), mdlen);


    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");

	char privKey[] = "rsaprivatekey.pem";

	BIO *privateKey;
	privateKey = BIO_new_file(privKey, "r");

	int siglen=0;
	//char * signature ="FIXSignatureFromServer";
    unsigned char signature[128];
	memset(signature, 0, sizeof(signature));

	//PEM_read_bio_RSAPrivateKey
	RSA * rsa_private = PEM_read_bio_RSAPrivateKey(privateKey, NULL, NULL, NULL);

	//RSA_private_encrypt
	siglen = RSA_private_encrypt(mdlen, (unsigned char *) hash_string, signature, rsa_private, RSA_PKCS1_PADDING);

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");

	//BIO_flush
	BIO_flush(hash);
	//SSL_write
	SSL_write(ssl, signature, sizeof(signature));

    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");

    //SSL_read
    char file[BUFFER_SIZE];
    memset(file,0,sizeof(file));
	string rFile;

	buf_len = SSL_read(ssl, file, 1024);

	rFile.assign(file);

    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	//BIO_flush
	//BIO_new_file
	//BIO_puts(server, "fnf");
    //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	//SSL_write(ssl, buffer, bytesRead);

	//while(stream >> buffer)
		//ssl_write(buffer)

    int bytesSent=0;
    
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	//SSL_shutdown
    //BIO_reset
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
