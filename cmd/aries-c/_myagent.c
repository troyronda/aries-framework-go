#include "aries.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printID(GoString id) {
	char *cID = malloc(id.n + 1);
	memcpy(cID, id.p, id.n);
	cID[id.n] = '\0';
	printf("C Agent Application has invitation with id: %s.\n", cID);
	free(cID);
}

int main() {
	printf("Hello from a C Agent Application.\n");
	Initialize();

	GoString id = {malloc(256), 256};
	CreateInvitation(&id);
	printID(id);

	return 0;
}
