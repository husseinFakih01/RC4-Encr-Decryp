#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
# define NUM_OF_SALT      8
# define NUM_OF_KEYS      16
# define SALT_STR_LEN     16
# define READ_WRITE_SIZE  4096

//input format: ./exe [-e/-d] [-salt/-nosalt] [key] [input] [output]
int main(int argc, char* argv[]) {
	int inputFile;
	int outputFile;
	unsigned char  saltedKey[NUM_OF_KEYS];
	RC4_KEY key;
	unsigned char inputBuffer[READ_WRITE_SIZE];
	unsigned char outputBuffer[READ_WRITE_SIZE];

	//validation that user inputs correct # of arguments
	if (argc < 6) {
		printf("Error: Not enough arguments.\n");
		printf("Format: ./exe [-e/-d] [-salt/-nosalt] [key] [input] [output]\n");
		exit(-1);
	}
	else if (argc > 6) {
		printf("Error: Too many arguments.\n");
		printf("Format: ./exe [-e/-d] [-salt/-nosalt] [key] [input] [output]\n");
		exit(-1);
	}

	//encrypt/decrypt option validation
	if (!(strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0)) {
		printf("Error: Incorrect [-e/-d] input.\n");
		printf("Format: ./exe [-e/-d] [-salt/-nosalt] [key] [input] [output]\n");
		exit(-1);
	}

	//salt/nosalt option validation
	if (!(strcmp(argv[2], "-salt") == 0 || strcmp(argv[2], "-nosalt") == 0)) {
		printf("Error: Incorrect [-salt/-nosalt] input.\n");
		printf("Format: ./exe [-e/-d] [-salt/-nosalt] [key] [input] [output]\n");
		exit(-1);
	}

	//input validation. checks if file exists
	if (access(argv[4], F_OK) != 0) {
		printf("Error: Input does not exist.\n");
		printf("Format: ./exe [-e/-d] [-salt/-nosalt] [key] [input] [output]\n");
		exit(-1);
	}

	//open input & create output files
	inputFile = open(argv[4], O_RDONLY);
	outputFile = open(argv[5], O_CREAT | O_WRONLY, 0644); //rw-r--r--



	//if salt option chosen
	if (strcmp(argv[2], "-salt") == 0) {
		unsigned char salt[NUM_OF_SALT];

		//if encryption option chosen
		if (strcmp(argv[1], "-e") == 0) {
			char saltString[SALT_STR_LEN];
			memset(saltString, 0, SALT_STR_LEN); //set saltString to all zeros before reading into it
			RAND_bytes(salt, NUM_OF_SALT); //randomly generate salt bytes
			sprintf(saltString, "Salted__%c%c%c%c%c%c%c", //string to store salt in ciphertext
				salt[0], salt[1], salt[2], salt[3],
				salt[4], salt[5], salt[6]);
			saltString[15] = salt[7]; //simple solution to fix salt[7] not being printed in properly
			write(outputFile, &saltString, SALT_STR_LEN); //write saltString to output file
		}

		//if decryption option chosen
		else if (strcmp(argv[1], "-d") == 0) {
			lseek(inputFile, 8, SEEK_SET); //read/write file offset to read saltString
			read(inputFile, salt, NUM_OF_SALT); //read salt chars into salt
		}

		//create key with salt
		if (!EVP_BytesToKey(EVP_rc4(), EVP_sha256(),
			salt, (unsigned char *)argv[3], strlen(argv[3]), 1, saltedKey, NULL))
		{
			printf("Error: Could not create encryption key.\n"); //if BytesToKey fails.
			exit(-1);
		}
		RC4_set_key(&key, NUM_OF_KEYS, (const unsigned char*)saltedKey); //using saltedKey hash to create RC4_KEY key.
	}

	//if nosalt option chosen
	else {
		//create key without salt
		if (!EVP_BytesToKey(EVP_rc4(), EVP_sha256(),
			NULL, (const unsigned char *)argv[3], (int)strlen(argv[3]), 1, saltedKey, NULL))
		{
			printf("Error: Could not create encryption key.\n"); //if BytesToKey fails.
			exit(-1);
		}
		RC4_set_key(&key, NUM_OF_KEYS, (const unsigned char*)saltedKey); //using saltedKey hash to create RC4_KEY key.
	}

	//write data to file. using while loop to only enncrypt & write by READ_WRITE_SIZE bytes at a time
	ssize_t bytesRead = 0; //counting bytes so program knows what buffer is if buffer < READ_WRITE_SIZE
	while (bytesRead = read(inputFile, &inputBuffer, READ_WRITE_SIZE)) {
		RC4(&key, bytesRead, (const unsigned char*)inputBuffer, (unsigned char*)outputBuffer); //encrypt inputBuffer to outputBuffer
		write(outputFile, &outputBuffer, bytesRead);
	}
	//close files
	close(inputFile);
	close(outputFile);

	return 0;
}
