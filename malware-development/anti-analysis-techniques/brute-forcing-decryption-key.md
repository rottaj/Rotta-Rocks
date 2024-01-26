# Brute Forcing Decryption Key

## Introduction

It's a bad thing to store any time of encryption key in plaintext within your binary. It's trivial for analysts to retrieve it.&#x20;

One way we can hide the encryption key is to encrypt it with another key and decrypt it at runtime. To avoid hardcoding, the key is brute forced.

## Key Encryption

In order for brute forcing encryption to work, we must provide the encryption/decryption functions with a **`hint byte`**. Knowing this one byte, before and after the encryption process makes decryption possible.

### H**ow a hint byte works:**

&#x20;If the hint byte is `BA` and when encrypted it becomes `71`, then the decryption process will brute force that value until it is reverted to `BA`, indicating the correct key was used.

<figure><img src="../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

### Key Encryption Function

The `GenerateProtectedKey` function takes a hint byte and prepends it as the first byte of the plaintext key.

We will use XOR encryption for this example:

```c
/*
  - HintByte: is the hint byte that will be saved as the key's first byte
  - sKey: the size of the key to generate
  - ppProtectedKey: pointer to a PBYTE buffer that will recieve the encrypted key
*/

VOID GenerateProtectedKey(IN BYTE HintByte, IN SIZE_T sKey, OUT PBYTE* ppProtectedKey) {
	
	// Genereting a seed
	srand(time(NULL));

	// 'b' is used as the key of the key encryption algorithm
	BYTE        b                = (rand() % 0xFF) + 0x01;
  
	// 'pKey' is where the original key will be generated to
	PBYTE       pKey             = (PBYTE)malloc(sKey);
  
	// 'pProtectedKey' is the encrypted version of 'pKey' using 'b'
	PBYTE       pProtectedKey    = (PBYTE)malloc(sKey);

	if (!pKey || !pProtectedKey)
		return;
	
	// Genereting another seed
	srand(time(NULL) * 2);

	// The key starts with the hint byte
	pKey[0] = HintByte;
	// generating the rest of the key
	for (int i = 1; i < sKey; i++){
		pKey[i] = (BYTE)rand() % 0xFF;
	}


	printf("[+] Generated Key Byte : 0x%0.2X \n\n", b);
	printf("[+] Original Key : ");
	PrintHex(pKey, sKey);

	// Encrypting the key using a xor encryption algorithm
	// Using 'b' as the key
	for (int i = 0; i < sKey; i++){
		pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
	}

	// Saving the encrypted key by pointer 
	*ppProtectedKey = pProtectedKey;

	// Freeing the raw key buffer
	free(pKey);
}
```

## Key Decryption

Since the decryption key is not stored anywhere, we must create a brute force function. We're using XOR as our encryption algorithm. **We will go through each byte and xor it with the hint byte until it we get 0.**

```c
if (((EncryptedKey[0] ^ b) - 0) == HintByte)
  // Then b's value is the xor encryption key
else
  // Then b's value is not the xor encryption key, try with a different b value
```



### Key Decryption Function

```c
/*	
	- HintByte : is the same hint byte that was used in the key generating function
	- pProtectedKey : the encrypted key
	- sKey : the key size
	- ppRealKey : pointer to a PBYTE buffer that will recieve the decrypted key
*/

BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {
	
	BYTE      b         = 0;
	PBYTE     pRealKey  = (PBYTE)malloc(sKey);

	if (!pRealKey)
		return NULL;

	while (1){

		// Using the hint byte, if this is equal, then we found the 'b' value needed to decrypt the key 
		if (((pProtectedKey[0] ^ b) - 0) == HintByte)
			break;
		// else, increment 'b' and try again
		else
			b++; 
	}
  
        // The reverse algorithm of the xor encryption, since 'b' now is known
	for (int i = 0; i < sKey; i++){
		pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
	}

        // Saving the decrypted key by pointer 
	*ppRealKey = pRealKey;

	return b;
}
```

\
