#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t secure_hash_function(uint32_t x){
	//From https://stackoverflow.com/questions/664014/what-integer-hash-function-are-good-that-accepts-an-integer-hash-key
	x = ((x >> 16) ^ x) * 0x45D9F3B;
    x = ((x >> 16) ^ x) * 0x45D9F3B;
    x = (x >> 16) ^ x;
    return x;
}

struct key{
	uint32_t k1[32];
	uint32_t k2[32];
};

void generate(struct key* pk, struct key* sk){
	for(int i = 0;i<32;i++){
		sk->k1[i] = (uint32_t) rand();
		sk->k2[i] = (uint32_t) rand();

		pk->k1[i] = secure_hash_function(sk->k1[i]);
		pk->k2[i] = secure_hash_function(sk->k2[i]);
	}
}

void sign(struct key* sk, uint32_t message, uint32_t* signature){
	for(int i=0; i<32; i++){
		signature[i] = ((message >> i) & 1) ? sk->k1[i] : sk->k2[i];
	}
}

int verify(uint32_t message, uint32_t* signature, struct key* pk){
	for(int i = 0; i<32; i++){
		//check if i-th value of signature matches hash of public key (index determined by message-bit at position i)
		if((message >> i) & 1){
			if(secure_hash_function(signature[i]) != pk->k1[i]){
				printf("\nFailed to verify signature at %dth bit. Excpected %u, Got %u\n",i, signature[i], pk->k1[i]);
				return 0;
			}
		}else{
			if(secure_hash_function(signature[i]) != pk->k2[i]){
				printf("\nFailed to verify signature at %dth bit: Excpected %u, Got %u\n",i, signature[i], pk->k2[i]);
				return 0;
			}
		}
	}
	return 1;
}

int main(){
	srand(time(NULL));

	uint32_t message = 0xDEADBEEF;
	uint32_t signature[32];
	struct key pk;
	struct key sk;

	generate(&pk , &sk);

	sign(&sk, message, signature);

	printf("Message: %X\nSignature: ( ",message);
	for(int i=0; i<32; i++)
		printf("%u ", signature[i]);
	printf(")\nValid signature: %d\n\n\n", verify(message, signature, &pk));

	printf("[ signing again with malformed secretkey.. ]\n");
	sk.k1[8] = (uint32_t) rand();
	sk.k2[8] = (uint32_t) rand();

	sign(&sk, message, signature);

	printf("\n\nMessage: %X\nSignature: ( ",message);
	for(int i=0; i<32; i++)
		printf("%u ", signature[i]);
	printf(")\nValid signature: %d\n", verify(message, signature, &pk));


}
