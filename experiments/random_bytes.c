#include<stdio.h>
#include<stdint.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include<time.h>
#include<string.h>

#define CRYPTO_SECRETKEYBYTES  43088     // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define CRYPTO_PUBLICKEYBYTES  21520     // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
#define CRYPTO_BYTES              32
#define CRYPTO_CIPHERTEXTBYTES 21632     // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8
#define BYTE_SEED_A 32
#define PARAMS_N 1344
#define PARAMS_NBAR 8
#define PARAMS_LOGQ 16

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#include<unistd.h>
#include<fcntl.h>

#define LWE_N 136   // Dimensionality of the lattice.
// We generate A is obtained by encrypting a striped matrix (where stripes
// are spaced 8 columns apart) in the AES128-ECB mode.
#define LWE_STRIPE_STEP 8
#define LWE_SEED_LENGTH 32

#if LWE_SEED_LENGTH != 32
#error "Seed length must be 32 bytes."
#endif

#if LWE_N % LWE_STRIPE_STEP != 0
#error "Matrix A is not well-defined."
#endif

#define LE_TO_UINT16(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
static int lock=-1;

void main()
{
    uint8_t randomness[2*CRYPTO_BYTES+BYTE_SEED_A];
    unsigned long long nbytes=CRYPTO_BYTES+CRYPTO_BYTES+BYTE_SEED_A;
    int r, n=nbytes, count=0;

    if(lock==-1)
    {
        do
        {
            lock=open("/dev/urandom", O_RDONLY);
            if(lock==-1)
            {
              sleep(0xFFFFFF);
            }
            
        }while (lock==-1);
        
    }
    while (n>0)
    {
        do
        {
           r=read(lock, randomness+count, n);
           if(r==-1)
           {
               sleep(0xFFFFF);
           }
        } while (r==-1);
        count+=r;
        n-=r;
    }
    

    printf("Random Bytes generated");

for(int i=0; i<nbytes; i++)
{
    printf("\n\nBYTE i %d %d", i, randomness[i]);
}

    uint8_t randomness_s=randomness[0];
    uint8_t *randomness_seedSE=&randomness[CRYPTO_BYTES];
    uint8_t shake_input_seedSE[1+CRYPTO_BYTES];
    uint8_t *randomness_z=&randomness[2*CRYPTO_BYTES];


    uint16_t B[PARAMS_N*PARAMS_NBAR]={0};
    uint16_t S[2*PARAMS_N*PARAMS_NBAR];
    uint16_t *E=(uint16_t *) &S[PARAMS_N * PARAMS_NBAR];


    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    uint8_t *pk_seedA=&pk[0];

    shake(pk_seedA, BYTE_SEED_A, randomness_z, BYTE_SEED_A);


    

    //Generate S and E and compute B=AS+E 
    shake_input_seedSE[0]=0x5F;
    memcpy(&shake_input_seedSE[1], randomness_seedSE, CRYPTO_BYTES);
     const uint8_t transpose = 1;
    printf("************************************\n\nPRINT S\n\n**********************************");
    gen_a((uint8_t *)S, shake_input_seedSE, transpose );
    printf("\n\n*********************************************PRINT E****************************************");
    gen_a((uint8_t *)E, shake_input_seedSE, transpose);
    
   

    

    
}

void shake(uint8_t *output, uint8_t outlen, uint8_t  *input, size_t inlen)
{
    uint64_t s[25];
    printf(" \nINLEN VALUE %lu", inlen);
    unsigned char t[SHAKE256_RATE];
    unsigned long long nblocks=outlen/SHAKE256_RATE;

    size_t i;
    EVP_MD_CTX* md_ctx = NULL;
    if ((md_ctx = EVP_MD_CTX_new()) == NULL)
    {
        printf("\n check 1");
        exit(0);
    }

    if (1 != EVP_DigestInit_ex(md_ctx, EVP_shake256(), NULL))
    {
        exit(0);
        printf("\n check 2");
    }

    if (1 != EVP_DigestUpdate(md_ctx, &input, inlen))
    {
        exit(0);
    }

    if ((output = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_shake256()))) == NULL)
    {
        exit(0);
    }
    outlen = EVP_MD_size(EVP_shake256());
    printf("\n%d", outlen);

    if (1 != EVP_DigestFinal_ex(md_ctx, output, &outlen))
    {
        OPENSSL_free(output);
        exit(0);
    }
    

    OPENSSL_free(output);
    EVP_MD_CTX_free(md_ctx);
}

uint16_t CDF_TABLE[7] = {9142, 23462, 30338, 32361, 32725, 32765, 32767};
uint16_t CDF_TABLE_LEN = 7;

    void frodo_sample_n(uint16_t  *s, const size_t n)
{
    unsigned int i, j;
    for(i=0; i<n;++i)
    {
        uint16_t sample=0;
        uint16_t prnd=s[i]>>1;
        uint16_t sign=s[i] & 0x1;

        for(j=0; j< (unsigned int)(CDF_TABLE_LEN-1); j++)
        {
            sample+=(uint16_t)(CDF_TABLE[j]-prnd)>> 15;
        }
        s[i]=((-sign)^ sample)+sign;
      }
     
    printf("FRODO SAMPLE");
    for(int j=0; j<n; j++)
    {
        printf("%d", s[j]);
    }
      
}
    

void gen_a(uint8_t* a,  uint8_t* seed, const uint8_t transpose) 
{
	
	int i, j;
	
	int ret = 0;
	/* We generate A using 256 bytes of memory at a time. */
	EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
	//EVP_CIPHER_CTX *aes_ctx = NULL;
	
	//EVP_CIPHER_CTX_reset(aes_ctx);
	
	if (1 != EVP_CIPHER_CTX_init(aes_ctx))
	{
		printf("Error1");
		goto err;
	}
	
	/*
	EVP_CIPHER_CTX_init(aes_ctx);
	
	if (aes_ctx == NULL) 
	{
		printf("Error1");
		goto err;
	}
	*/
	//EVP_EncryptInit_ex() sets up cipher context ctx for encryption with cipher type from ENGINE impl. ctx must be created before calling this function
	if (1 != EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_ecb(), NULL, seed, NULL)) 
	{
		printf("Error2");
		goto err;
	}

	//EVP_CIPHER_CTX_set_padding(aes_ctx, 0);  // no padding in the ECB mode
	if (1 != EVP_CIPHER_CTX_set_padding(aes_ctx, 0))
	{
		printf("Error3");
		goto err;
	}
	size_t a_len = LWE_N * LWE_N * sizeof(uint16_t);
	//printf("%llu\n", a_len);
	//a = (uint16_t)malloc((LWE_N * LWE_N) * sizeof(uint16_t));
	
	memset(a, 0, a_len);

	
	for (i = 0; i < LWE_N; i++)
		for (j = 0; j < LWE_N; j += LWE_STRIPE_STEP) 
		{
			a[i * LWE_N + j] = i;
			a[i * LWE_N + j + 1] = j;
		}
	for (int k = 0; k < a_len; k++)
		{
			printf(" %02x",a[k]);
		}
	
	int outlen;

	if (1 != EVP_EncryptUpdate(aes_ctx, (unsigned char*)a, &outlen,
		(unsigned char*)a, a_len) ||
		((size_t)outlen != a_len)) {
		goto err;
	}

	if (1 != EVP_EncryptFinal_ex(aes_ctx, (unsigned char*)a, &outlen)) {
		// not necessary since padding is disabled
		goto err;
	}

	if (transpose) // in-situ transpose of the square matrix
		for (i = 0; i < LWE_N; i++)
			for (j = i + 1; j < LWE_N; j++) {
				uint16_t tmp = a[i * LWE_N + j];
				a[i * LWE_N + j] = a[j * LWE_N + i];
				a[j * LWE_N + i] = tmp;
			}
	
	ret = 1;
	
err:
	if (aes_ctx != NULL) {
		EVP_CIPHER_CTX_cleanup(aes_ctx);
	}
	
	
	printf("\n Successful execution ...!!!\n");
}