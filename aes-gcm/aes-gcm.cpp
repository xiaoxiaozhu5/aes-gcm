// ConsoleApplication37.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <iostream>

#include "win-crypt.h"
#include "win-encrypt.h"
#include "win-decrypt.h"

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

const char key[16] = {0x12, 0x23, 0x44, 0x23, 0x23, 0x33, 0x44, 0x11, 0x12, 0x23, 0x44, 0x23, 0x23, 0x33, 0x44, 0x11};
const char iv[12] = {0x12, 0x23, 0x44, 0x23, 0x23, 0x33, 0x44, 0x11, 0x12, 0x23, 0x44, 0x23};
const char tag[16] = {0x12, 0x23, 0x44, 0x23, 0x23, 0x33, 0x44, 0x11, 0x12, 0x23, 0x44, 0x23, 0x23, 0x33, 0x44, 0x11};
const char aad[16] = {0x12, 0x23, 0x44, 0x23, 0x23, 0x33, 0x44, 0x11, 0x12, 0x23, 0x44, 0x23, 0x23, 0x33, 0x44, 0x11};

void test()
{
	static const char* const pt = "hello world";
	const struct ubiq_platform_algorithm* alg = nullptr;
	void* ctbuf = NULL;
	size_t ctlen;
	void* ctbuf2 = NULL;
	size_t ctlen2;
	void* tag = NULL;
	size_t taglen;

	void* dpt = NULL;
	size_t ptlen = 0;
	void* dpt2 = NULL;
	size_t ptlen2 = 0;
	do
	{
		int rc = ubiq_platform_algorithm_get_byid(1, &alg);
		if (rc != 0)
		{
			std::cout << "get failed:" << rc << std::endl;
			break;
		}
		//encryption
		{
			struct ubiq_support_cipher_context* ctx = nullptr;
			rc = ubiq_support_encryption_init(alg, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), &ctx);
			if (rc != 0)
			{
				std::cout << "init failed:" << rc << std::endl;
				break;
			}
			rc = ubiq_support_encryption_update(ctx, pt, strlen(pt), &ctbuf, &ctlen);
			if (rc != 0)
			{
				std::cout << "update failed:" << rc << std::endl;
				break;
			}
			rc = ubiq_support_encryption_finalize(ctx, &ctbuf2, &ctlen2, &tag, &taglen);
			if (rc != 0)
			{
				std::cout << "finalize failed:" << rc << std::endl;
				break;
			}
		}
		//decryption
		{
			struct ubiq_support_cipher_context* ctx = nullptr;
			rc = ubiq_support_decryption_init(alg, key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad), &ctx);
			if (rc != 0)
			{
				std::cout << "init failed:" << rc << std::endl;
				break;
			}
			rc = ubiq_support_decryption_update(ctx, ctbuf2, ctlen2, &dpt, &ptlen);
			if (rc != 0)
			{
				std::cout << "update failed:" << rc << std::endl;
				break;
			}
			rc = ubiq_support_decryption_finalize(ctx, tag, taglen, &dpt2, &ptlen2);
			if (rc != 0)
			{
				std::cout << "finalize failed:" << rc << std::endl;
				break;
			}
			printf("%.*s\n", (int)ptlen2, (char*)dpt2);
		}

	} while (false);
	free(tag);
	free(ctbuf2);
	free(ctbuf);

	free(dpt);
	free(dpt2);
}

int main()
{
	static const char* const pt = "hello world";

	void* ctbuf = NULL;
	size_t ctlen;
	int res = ubiq_platform_encrypt(key, sizeof(key), iv, sizeof(iv), tag, sizeof(tag), aad, sizeof(aad), pt, strlen(pt),
	                            &ctbuf, &ctlen);
	if (res != 0)
	{
		std::cout << "encrypt failed:" << res << std::endl;
		return 1;
	}

	void* oribuf = NULL;
	size_t orilen;

	res = ubiq_platform_decrypt(key, sizeof(key), iv, sizeof(iv), tag, sizeof(tag), aad, sizeof(aad), ctbuf, ctlen,
	                            &oribuf, &orilen);
	if (res != 0)
	{
		std::cout << "decrypt failed:" << res << std::endl;
		return 1;
	}
	printf("%.*s\n", (int)orilen, (char*)oribuf);

	free(ctbuf);
	free(oribuf);

	test();
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
