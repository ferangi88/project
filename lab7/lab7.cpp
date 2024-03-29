#include <iostream>#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>		//for RSA

using namespace std;

int main(int argc, char *argv[])
{
	char infilename[] = "Louton.txt";
	char outfilename[] = "DocOut.txt";
	char privKey[] = "rsaprivatekey.pem";
	char pubKey[] = "rsapublickey.pem";
	char hash_code_sig[] = "hash-code-signature.bin";

	unsigned char buffer[1024];
	unsigned char buffer2[1024];
	unsigned char buffer3[1024];

	memset(buffer,0,sizeof(buffer));
	memset(buffer2,0,sizeof(buffer2));
	memset(buffer3,0,sizeof(buffer3));

	/*for(int i = 0; i < 1024; i++)
	{
		buffer[i] = 0;
		buffer2[i] = 0;
		buffer3[i] = 0;
	}*/

	BIO *binfile, *boutfile, *hash, *privateKey, *publicKey, *hash_sig;
	binfile = BIO_new_file(infilename, "r");		//file to read ("r")
	privateKey = BIO_new_file(privKey, "r");
	publicKey = BIO_new_file(pubKey, "r");
	boutfile = BIO_new_file(outfilename, "w") ;		//file to write ("w")
	hash_sig = BIO_new_file(hash_code_sig, "w");
	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());

	//Chain on the input
	BIO_push(hash, binfile);

	//Chain on the output
	BIO_push(hash, boutfile);

	int actualRead, actualWritten;

	while((actualRead = BIO_read(hash, buffer, 1024)) >= 1)
	{
		//Could send this to multiple chains from here
		actualWritten = BIO_write(boutfile, buffer, actualRead);
	}

	//Get digest
	char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen = BIO_gets(hash, mdbuf, EVP_MAX_MD_SIZE);
	for(int i = 0; i < mdlen; i++)
	{
		//Print two hexadecimal digits (8 bits or 1 character) at a time
		printf("%02x", mdbuf[i] & 0xFF);
	}
	printf("\n");

	int encrypt_size = 0;
	RSA * rsa_private = PEM_read_bio_RSAPrivateKey(privateKey, NULL, NULL, NULL);
	encrypt_size = RSA_private_encrypt(EVP_MAX_MD_SIZE, (unsigned char *) mdbuf, buffer2, rsa_private, RSA_PKCS1_PADDING);

	for(int i = 0; i < encrypt_size; i++)
	{
		//Print two hexadecimal digits (8 bits or 1 character) at a time
		printf("%02x", buffer2[i] & 0xFF);
	}
	printf("\n");
/*
  	FILE * pFile;
  	pFile = fopen ( hash_code_sig , "w" );
  	fwrite (buffer2 , 1 , sizeof(buffer2) , pFile );
  	fclose (pFile);
*/

	RSA * rsa_public = PEM_read_bio_RSA_PUBKEY(publicKey, NULL, NULL, NULL);
	RSA_public_decrypt(encrypt_size, (unsigned char *)buffer2, buffer3, rsa_public, RSA_PKCS1_PADDING);

	for(int i = 0; i < mdlen; i++)
	{
		//Print two hexadecimal digits (8 bits or 1 character) at a time
		printf("%02x", buffer3[i] & 0xFF);
	}
	printf("\n");

	//BIO_free_all(binfile);
	//BIO_free_all(boutfile);
	//BIO_free_all(hash);

	return 0;
}
