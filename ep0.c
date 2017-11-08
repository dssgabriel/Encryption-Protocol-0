/*
  Ecryption Protocol Level 0
  This code is under GPL ...
  
  AJE
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <emmintrin.h>

//Memory alignment : 64Bytes ==> 1 Cachelines
#define ALIGN    64

#define Y_MAX    8
#define Z_MAX    8

//Lengths in bits
#define KEY_LEN  64 
#define BLK_LEN  64
#define BLK_MAX  1024 * 1024 //1M blocks = 1M * 8 Bytes = 8 MBytes = 64Mbits

#define PAD_MIN  8

#define CST_MAX  8

#define ROT_VAL  4

#define EN_MOD   1
#define DE_MOD   0

//Encryption and decryption macros
#define ENCRYPT(ef, key, rot, blk) rot(ef(blk, key)) 
#define DECRYPT(ef, key, rot, blk) ef(rot(blk), key)

//Totally random values !
uint64_t A[CST_MAX] = { 0xe92a0b341cd8b2db, 0xa7798872872ec571, 
			0x7760781c8e596ff9, 0xaa639475751f8658, 
			0xc658f7a60513a8bb, 0xce4ca6fb745cce45, 
			0x813543fce0b55beb, 0x98ea8de5adb20b0c }; 

uint64_t B[CST_MAX] = { 0x693a89341cdcb29a, 0xe7f88a73072ed551, 
			0xb644781aee186ff9, 0x396b140d6b1e86d8, 
			0x4278882744ed889b, 0xbd232ebb845515db, 
			0xf67af36f65b4dc45, 0xaf0518b0e4e784fa };

uint64_t C[CST_MAX] = { 0xa5c338b49a24d9f3, 0xf0a660ea2249bd76, 
			0x46e3e900734c6289, 0xfe7d89249ddc0c62, 
			0x2150557520be4540, 0x2e540eda6540033 , 
			0xaa2e0357fefdee2 , 0x3c0fa940fe97d821 };
 
uint64_t D[CST_MAX] = { 0xda2c454b65df264d, 0x4fd89d145db652a9, 
			0x783816f9ecf29d76, 0x928af6a37c22f31d, 
			0x5a8fd50b9ebf9a9f, 0x8e753752a9a22452, 
			0x8212af590511a6b3, 0xf41fc3ea483da828 };

//Random scrambling table  
uint64_t Z[Z_MAX]; // Z = A ^ B
uint64_t Y[Y_MAX]; // Y = C ^ D

//
typedef unsigned char byte;

//Initializing scrambling tables Y & Z
void init_YZ()
{
  for (uint64_t i = 0; i < CST_MAX; i++)
    {
      Y[i] = C[i] ^ D[i];
      Z[i] = A[i] ^ B[i];
    }
}

//Padding a stream with a 0 block
uint64_t pad(uint64_t *stream, uint64_t nb_bytes, uint64_t mode)
{
  uint64_t nb_blocks = nb_bytes >> 3;
  
  if (mode == EN_MOD)
    {  if (nb_bytes & 7)
	nb_blocks++;
      
      stream[nb_blocks + 1] = stream[nb_blocks + 2] = 0;
    }
  
  return nb_blocks + mode;
}

//Converting  
uint64_t bytes_to_uint64(byte *stream)
{
  return 
    ((uint64_t) stream[0] << 56) +
    ((uint64_t) stream[1] << 48) +
    ((uint64_t) stream[2] << 40) +
    ((uint64_t) stream[3] << 32) +
    ((uint64_t) stream[4] << 24) +
    ((uint64_t) stream[5] << 16) +
    ((uint64_t) stream[6] <<  8) +
    ((uint64_t) stream[7] <<  0);
}

//Left rotate 
uint64_t lrot64(uint64_t x)
{ return (x << ROT_VAL) | (x >> ((sizeof(uint64_t) << 3) - ROT_VAL)); }

//Right rotate
uint64_t rrot64(uint64_t x)
{ return (x >> ROT_VAL) | (x << ((sizeof(uint64_t) << 3) - ROT_VAL)); }

//Encryption routine
uint64_t encrypt_block(uint64_t block, uint64_t key)
{ 
  uint64_t tmp;
  
  //Randomizing the text with junk ! 
  for (uint64_t i = 0; i < (Y_MAX & Z_MAX); i++)
    tmp = (block ^ key ^ ~(Z[i] ^ Y[i])); 
  
  return tmp;
}

//
int main(int argc, char **argv)
{
  //Parameters check !
  if (argc < 4)
    return printf("Usage : %s -[d | e] [KEY] [INPUT FILE] [OUTPUT FILE]\n", argv[0]), -1;

  byte mode;
 
  if (!strncmp(argv[1], "-d", 2))
    mode = DE_MOD;
  else
    if (!strncmp(argv[1], "-e", 2))
      mode = EN_MOD;
    else
      return printf("Error : mode unrecognized"), -3;
  
  //Declarations ...
  uint64_t key = bytes_to_uint64(argv[2]);
  FILE *fin = fopen(argv[3], "rb"), *fout = fopen(argv[4], "wb");
  uint64_t *cl_txt = _mm_malloc(sizeof(uint64_t) * BLK_MAX, ALIGN);

  //Usual file checks !
  if (!fin)  return printf("Error : cannot open input file %s", argv[2]), -2;
  if (!fout) return printf("Error : cannot create output  file %s", argv[2]), -2;

  //Initialization of random scrambling tables
  init_YZ();

  //Loading input text
  uint64_t nb_bytes = fread(cl_txt, sizeof(byte), BLK_MAX * sizeof(byte), fin) + 1;
  
  uint64_t nb_blocks = pad(cl_txt, nb_bytes, mode);
    
  for (uint64_t i = 0; i < nb_blocks; i++)
    {
      uint64_t en_block = (mode == EN_MOD) ? ENCRYPT(encrypt_block, key, lrot64, cl_txt[i]) : 
	                                     DECRYPT(encrypt_block, key, rrot64, cl_txt[i]);
      
      fwrite(&en_block, sizeof(uint64_t), 1, fout); //Dumping encrypted text 
    }
  
  fclose(fin);
  fclose(fout);
  
  _mm_free(cl_txt);
  
  return 0;
}
