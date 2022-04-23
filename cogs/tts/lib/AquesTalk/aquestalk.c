
#include <stdio.h>
#include <stdlib.h>
#include "AquesTalk.h"


int main(int argc, char **argv) {
	int size;
	char chars[8000];

	if (fgets(chars, 8000 - 1, stdin) == 0)
		return 0;

	unsigned char *wav = AquesTalk_Synthe_Utf8(
		chars, atoi(argv[1]), &size
	);

	if (wav == 0) {
		fprintf(stderr, "ERR:%d\n", size);
		return -1;
	} else {
		fwrite(wav, 1, size, stdout);
	}

	AquesTalk_FreeWave(wav);
 
	return 0;
}
