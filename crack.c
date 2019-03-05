#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rc4_encrypt(void* buffer, void* input, size_t len, const char *key);

char data[2728312+1];

char outdata[2728312+1];

int main(int argc, char* argv[])
{
	if(argc < 1)
	{
		printf("Usage: %s file [key]\n", argv[1]);
		exit(1);
	}

	FILE* file = fopen(argv[1],"rb");

	fread(data, sizeof(data)-1, 1, file);

	data[sizeof(data)-1] = 0;

	fclose(file);

	char key[] = "000000-000000-000000-000000-000000";

	int l = 0;

	if(argc > 2)
	{
		l = strlen(argv[2]);
		for(int i = 0; i < l; ++i)
		{
			key[i] = argv[2][i];
		}
		if(key[l] == '-')
			l++;
	}

	key[l] = key[l+1] = 'X';

	int flag = 0;

	for(char c = 'A'; c <= 'Z' && !flag; ++c)
	{
		key[l] = c;
		for(char d = 'A'; d <= 'Z'; ++d)
		{
			key[l+1] = d;
			rc4_encrypt(outdata, data, sizeof(data)-1, key);
			if(outdata[0] == 127 && outdata[1] == 69 && outdata[2] == 76 && outdata[3] == 70)
			{
				flag = 1;
				break;
			}
		}
	}

	if(!flag)
	{
		printf("Failed to decrypt.\n");
		exit(1);
	}
	key[l+2] = '\0';
	printf(key);

	char path[128];
	sprintf(path, "%s.so", argv[1]);

	file = fopen(path, "wb");

	int x = fwrite(outdata, sizeof(outdata)-1, 1, file);
	//printf("Wrote %ld bytes to %s\n", sizeof(outdata)-1, path);
	fclose(file);
}
