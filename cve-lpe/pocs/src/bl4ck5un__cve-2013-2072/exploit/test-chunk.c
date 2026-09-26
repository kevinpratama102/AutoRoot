#include<stdio.h>
#include<stdlib.h>
#include<stddef.h>

int main(){
	printf("size_t=%lu\n", sizeof(size_t));
	long *p = malloc(1024);
	int i;
	printf("[%p] %lx\n", p-1, *(p-1));
	printf("[%p] %lx\n", p-2, *(p-2));

	*(p-1) = 0x12345678ABCDEF00;
	printf("[%p] %lx\n", p-1, *(p-1));

	FILE *fp = fopen("heap_dump.dat", "wb");
	fwrite(p-2, sizeof(char), 1024 + 2*sizeof(size_t), fp);	
	return 0;
}
