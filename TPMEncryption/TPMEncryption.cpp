
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <iostream>

#define NT_SUCCESS(status)		(((NTSTATUS)(status)) >= 0)

#define SAMPLE_KEY_ID	L"Sample Key Identifier"

// AES-256 has 32-byte keys and 16-byte blocks.
#define AES_KEY_SIZE	32
#define AES_IV_SIZE		16

// A tiny struct that tells us what part of a vault is encrypted AES key
// and what part is AES-encrypted data.
typedef struct {
	BYTE version = 1;
	DWORD cbAesKey;
	DWORD cbData;
} VAULT_HEADER;

/*
 * Fills out a struct with padding information for OAEP using a static label.
 */
BCRYPT_OAEP_PADDING_INFO CreatePaddingInfo(void) {
	PSTR szLabel = "TPM Encryption";
	BCRYPT_OAEP_PADDING_INFO paddingInfo = {
		BCRYPT_SHA256_ALGORITHM,
		(PUCHAR)szLabel,
		(ULONG)strlen(szLabel) + 1
	};

	return paddingInfo;
}

/*
 * Encrypts a byte buffer using a TPM-stored RSA key.
 * If the given key identifier doesn't exist, it is created.
 * The buffer in *ppDataOut is allocated by this function; after the caller is 
 *     done with it, free it with delete[].
 * Returns TRUE on success and FALSE on failure.
 */
BOOLEAN EncryptWithTPM(LPCWSTR keyId, PBYTE pDataIn, DWORD cbDataIn, PBYTE* ppDataOut, PDWORD pcbDataOut) {
	BOOLEAN success = FALSE;

	SECURITY_STATUS	status;

	NCRYPT_KEY_HANDLE hRsaKey = NULL;
	NCRYPT_PROV_HANDLE hStorageProv = NULL;

	// Open the TPM-based key storage provider.
	status = NCryptOpenStorageProvider(&hStorageProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error opening TPM storage provider: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Attempt to open the key with our key identifier.
	// If this fails, create a new key with that identifier.
	status = NCryptOpenKey(hStorageProv, &hRsaKey, keyId, 0, 0);
	if (status == NTE_BAD_KEYSET) {
		std::cerr << "Key '" << keyId << "' does not exist. Creating it..." << std::endl;
		status = NCryptCreatePersistedKey(hStorageProv, &hRsaKey, BCRYPT_RSA_ALGORITHM, keyId, 0, 0);
		if (status != ERROR_SUCCESS) {
			std::cerr << "Error creating key: " << std::hex << status << std::endl;
			goto cleanup;
		}

		// Newly-created keys must be finalized before use.
		status = NCryptFinalizeKey(hRsaKey, 0);
		if (status != ERROR_SUCCESS) {
			std::cerr << "Error finalizing key: " << std::hex << status << std::endl;
			goto cleanup;
		}
	}
	else if (status != ERROR_SUCCESS) {
		std::cerr << "Error opening key: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Find out how large the encrypted data will be.
	DWORD dwBufferSize;
	BCRYPT_OAEP_PADDING_INFO paddingInfo = CreatePaddingInfo();

	status = NCryptEncrypt(hRsaKey, pDataIn, cbDataIn, &paddingInfo, NULL, 0, &dwBufferSize, NCRYPT_PAD_OAEP_FLAG);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error determining the size of the encrypted buffer: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Create a buffer for the encrypted data, and encrypt it!
	*ppDataOut = new BYTE[dwBufferSize];
	status = NCryptEncrypt(hRsaKey, pDataIn, cbDataIn, &paddingInfo, *ppDataOut, dwBufferSize, pcbDataOut, NCRYPT_PAD_OAEP_FLAG);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error encrypting data: " << std::hex << status << std::endl;
		goto cleanup;
	}

	success = TRUE;

cleanup:
	if (hRsaKey != NULL) {
		NCryptFreeObject(hRsaKey);
	}

	if (hStorageProv != NULL) {
		NCryptFreeObject(hStorageProv);
	}

	return success;
}

/*
 * Decrypts the given byte buffer with a TPM-stored RSA key.
 * On return, *ppDataOut points to a byte buffer containing the decrypted data.
 * After finishing with the decrypted data, free it with delete[].
 * Returns TRUE on success and FALSE on failure.
 */
BOOLEAN DecryptWithTPM(LPCWSTR keyId, PBYTE pDataIn, DWORD cbDataIn, PBYTE* ppDataOut, PDWORD pcbDataOut) {
	BOOLEAN success = FALSE;

	SECURITY_STATUS	status;

	NCRYPT_KEY_HANDLE hRsaKey = NULL;
	NCRYPT_PROV_HANDLE hStorageProv = NULL;

	// Open the TPM-based key storage provider.
	status = NCryptOpenStorageProvider(&hStorageProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error opening TPM storage provider: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Attempt to open the key with our key identifier.
	status = NCryptOpenKey(hStorageProv, &hRsaKey, keyId, 0, 0);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error opening key: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Find out how large the decrypted data will be.
	DWORD dwBufferSize;
	BCRYPT_OAEP_PADDING_INFO paddingInfo = CreatePaddingInfo();
	status = NCryptDecrypt(hRsaKey, pDataIn, cbDataIn, &paddingInfo, NULL, 0, &dwBufferSize, NCRYPT_PAD_OAEP_FLAG);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error computing decrypted data size: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Actually decrypt.
	*ppDataOut = new BYTE[dwBufferSize];
	status = NCryptDecrypt(hRsaKey, pDataIn, cbDataIn, &paddingInfo, *ppDataOut, dwBufferSize, pcbDataOut, NCRYPT_PAD_OAEP_FLAG);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error decrypting data: " << std::hex << status << std::endl;
		goto cleanup;
	}

	success = TRUE;

cleanup:
	if (hRsaKey != NULL) {
		NCryptFreeObject(hRsaKey);
	}

	if (hStorageProv != NULL) {
		NCryptFreeObject(hStorageProv);
	}

	return success;
}

/*
 * Encrypts the given byte buffer using AES.
 * The keysize (AES-128, AES-256, etc.) is determined by the key handle hAesKey.
 * cbIV must be equal to the AES block size (16).
 * On return, *ppCiphertext points to a byte buffer containing encrypted data. Free it with delete[].
 * Returns TRUE on success, FALSE on failure.
 */
BOOLEAN EncryptWithAES(
	BCRYPT_KEY_HANDLE hAesKey,
	PBYTE pIV, DWORD cbIV,
	PBYTE pPlaintext, DWORD cbPlaintext,
	PBYTE* ppCiphertext, PDWORD pcbCiphertext
) {
	BOOLEAN success = FALSE;
	NTSTATUS status;

	// The IV buffer is mutated during encryption, so we make a copy of it and use that
	// so we can keep the input buffer the same.
	PBYTE pIVCopy = new BYTE[cbIV];
	CopyMemory(pIVCopy, pIV, cbIV);

	// Determine the output buffer size.
	DWORD dwBufferSize;
	status = BCryptEncrypt(hAesKey, pPlaintext, cbPlaintext, NULL, pIVCopy, cbIV, NULL, 0, &dwBufferSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		std::cerr << "Error determing AES output buffer size: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Create the buffer and put encrypted data into it.
	*ppCiphertext = new BYTE[dwBufferSize];
	status = BCryptEncrypt(hAesKey, pPlaintext, cbPlaintext, NULL, pIVCopy, cbIV, *ppCiphertext, dwBufferSize, pcbCiphertext, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		std::cerr << "Error AES-encrypting data: " << std::hex << status << std::endl;
		goto cleanup;
	}

	success = TRUE;

cleanup:
	delete[] pIVCopy;

	return success;
}

/*
* Decrypts the given byte buffer using AES.
* The keysize (AES-128, AES-256, etc.) is determined by the key handle hAesKey.
* cbIV must be equal to the AES block size (16).
* On return, *ppPlaintext points to a byte buffer containing decrypted data. Free it with delete[].
* Returns TRUE on success, FALSE on failure.
*/
BOOLEAN DecryptWithAES(
	BCRYPT_KEY_HANDLE hAesKey,
	PBYTE pIV, DWORD cbIV,
	PBYTE pCiphertext, DWORD cbCiphertext,
	PBYTE* ppPlaintext, PDWORD pcbPlaintext
) {
	BOOLEAN success = FALSE;
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAesAlg = NULL;

	// Determine the output buffer size.
	DWORD dwBufferSize;
	status = BCryptDecrypt(hAesKey, pCiphertext, cbCiphertext, NULL, pIV, cbIV, NULL, 0, &dwBufferSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		std::cerr << "Error determing AES output buffer size: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Create the buffer and put decrypted data into it.
	*ppPlaintext = new BYTE[dwBufferSize];
	status = BCryptDecrypt(hAesKey, pCiphertext, cbCiphertext, NULL, pIV, cbIV, *ppPlaintext, dwBufferSize, pcbPlaintext, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		std::cerr << "Error AES-decrypting data: " << std::hex << status << std::endl;
		goto cleanup;
	}

	success = TRUE;

cleanup:
	return success;
}

/*
 * Generates cbRandom random bytes using a TPM.
 * Returns a pointer to a buffer of length cbRandom filled with random bytes.
 * Free the buffer with delete[].
 */
PBYTE GenerateRandomBytes(DWORD cbRandom) {
	BCRYPT_ALG_HANDLE hRandAlg;
	PBYTE result = NULL;

	// Open the TPM-based random number generator.
	SECURITY_STATUS status = BCryptOpenAlgorithmProvider(&hRandAlg, BCRYPT_RNG_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error opening RNG provider: " << std::hex << status << std::endl;
		goto cleanup;
	}

	// Generate some random bytes!
	result = new BYTE[cbRandom];
	status = BCryptGenRandom(hRandAlg, result, cbRandom, 0);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Error generating random bytes: " << std::hex << status << std::endl;
		delete[] result;
		result = NULL;

		goto cleanup;
	}

cleanup:
	if (hRandAlg != NULL) {
		BCryptCloseAlgorithmProvider(hRandAlg, 0);
	}

	return result;
}

/*
 * Exports an AES key and IV to a byte buffer.
 * On return, *ppAesKeyBlob points to a byte buffer containing the exported AES key,
 *     followed by the given IV.
 *
 * Returns TRUE on success and FALSE on failure.
 */
BOOLEAN ExportAesKey(BCRYPT_KEY_HANDLE hAesKey, PBYTE pIV, DWORD cbIV, PBYTE* ppAesKeyBlob, PDWORD pcbAesKeyBlob) {
	// Determine how large the buffer should be.
	DWORD dwBufferSize;
	NTSTATUS status = BCryptExportKey(hAesKey, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &dwBufferSize, 0);
	if (!NT_SUCCESS(status)) {
		std::cerr << "Error determining AES key export buffer size: " << std::hex << status << std::endl;
		return FALSE;
	}

	// Allocate the buffer, making sure there's room for the IV as well.
	PBYTE pBuffer = new BYTE[dwBufferSize + AES_IV_SIZE];

	// Actually export the key.
	DWORD dwIvOffset;
	status = BCryptExportKey(hAesKey, NULL, BCRYPT_KEY_DATA_BLOB, pBuffer, dwBufferSize, &dwIvOffset, 0);
	if (!NT_SUCCESS(status)) {
		std::cerr << "Error exporting AES key: " << std::hex << status << std::endl;
		delete[] pBuffer;
		return FALSE;
	}

	// Stick the IV in the buffer after the exported key blob.
	CopyMemory(pBuffer + dwIvOffset, pIV, cbIV);

	*pcbAesKeyBlob = dwBufferSize + AES_IV_SIZE;
	*ppAesKeyBlob = pBuffer;

	return TRUE;
}

/*
 * Convenience method to initialize a BCrypt AES provider in CBC mode.
 */
BOOLEAN CreateAesProvider(BCRYPT_ALG_HANDLE* phAesAlg) {
	NTSTATUS ntStatus = BCryptOpenAlgorithmProvider(phAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(ntStatus)) {
		std::cerr << "Error opening AES algorithm provider: " << std::hex << ntStatus << std::endl;
		return FALSE;
	}

	// Tell the AES provider to use CBC mode.
	ntStatus = BCryptSetProperty(*phAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(ntStatus)) {
		std::cerr << "Error setting AES provider to CBC mode: " << std::hex << ntStatus << std::endl;
		return FALSE;
	}

	return TRUE;
}

/*
 * Encrypts the given data, ultimately protecting it with a TPM-stored RSA key.
 *
 * On return *ppDataOut points to a buffer with the following structure:
 * 
 * [ VAULT_HEADER structure                    ]       9 bytes
 * [ AES key encrypted with TPM-stored RSA key ]     256 bytes
 * [ Data encrypted by ^ this AES key ^        ]  16 * n bytes
 *
 * The RSA key used to protect the AES key is identified by SAMPLE_KEY_ID; if
 * no key with this identifier is stored in the TPM, one is created.
 *
 * Returns TRUE on success and FALSE on failure.
 */
BOOLEAN EncryptVault(PBYTE pDataIn, DWORD cbDataIn, PBYTE* ppDataOut, PDWORD cbDataOut) {
	BOOLEAN success = FALSE;

	// Lots and lots of objects are needed.
	BCRYPT_ALG_HANDLE hAesAlg = NULL;
	BCRYPT_KEY_HANDLE hAesKey = NULL;

	PBYTE pAesKey = NULL;
	PBYTE pAesIV = NULL;

	PBYTE pEncryptedData = NULL;
	DWORD cbEncryptedData;

	PBYTE pAesKeyBlob = NULL;
	DWORD cbAesKeyBlob;

	PBYTE pEncryptedAesKeyBlob = NULL;
	DWORD cbEncryptedAesKeyBlob;

	VAULT_HEADER header;

	// Generate a new AES key and IV using random bytes from the TPM.
	pAesKey = GenerateRandomBytes(AES_KEY_SIZE);
	pAesIV = GenerateRandomBytes(AES_IV_SIZE);

	if (pAesKey == NULL || pAesIV == NULL) {
		goto cleanup;
	}

	std::cerr << "Successfully generated new random AES key and IV." << std::endl;

	// Create an AES algorithm provider. This runs on the CPU instead of the TPM for speed.
	if (!CreateAesProvider(&hAesAlg)) {
		goto cleanup;
	}

	// Create a BCrypt key object for the AES key bytes we were given.
	NTSTATUS ntStatus = BCryptGenerateSymmetricKey(hAesAlg, &hAesKey, NULL, 0, pAesKey, AES_KEY_SIZE, 0);
	if (!NT_SUCCESS(ntStatus)) {
		std::cerr << "Error turning key bytes into a key object: " << std::hex << ntStatus << std::endl;
		goto cleanup;
	}

	// Encrypt the input data using the AES key we've built.
	if (!EncryptWithAES(hAesKey, pAesIV, AES_IV_SIZE, pDataIn, cbDataIn, &pEncryptedData, &cbEncryptedData)) {
		goto cleanup;
	}

	std::cerr << "Successfully encrypted data with AES key." << std::endl;

	// Export the AES key object and IV to a byte buffer.
	if (!ExportAesKey(hAesKey, pAesIV, AES_IV_SIZE, &pAesKeyBlob, &cbAesKeyBlob)) {
		goto cleanup;
	}

	// Encrypt the buffer with the key and IV using an RSA key stored in the TPM.
	// All processing is done in the TPM, and the private part of the key cannot be extracted.
	if (!EncryptWithTPM(SAMPLE_KEY_ID, pAesKeyBlob, cbAesKeyBlob, &pEncryptedAesKeyBlob, &cbEncryptedAesKeyBlob)) {
		goto cleanup;
	}

	std::cerr << "Successfully encrypted AES key with TPM-stored RSA key." << std::endl;

	// Set up a header to make data extraction easier.
	header.cbAesKey = cbEncryptedAesKeyBlob;
	header.cbData = cbEncryptedData;

	// Combine the (AES-encrypted) data with the (RSA-encrypted) AES key and IV and the header.
	*cbDataOut = sizeof(VAULT_HEADER) + cbEncryptedAesKeyBlob + cbEncryptedData;
	*ppDataOut = new BYTE[*cbDataOut];

	CopyMemory(*ppDataOut, &header, sizeof(VAULT_HEADER));
	CopyMemory(*ppDataOut + sizeof(VAULT_HEADER), pEncryptedAesKeyBlob, cbEncryptedAesKeyBlob);
	CopyMemory(*ppDataOut + sizeof(VAULT_HEADER) + cbEncryptedAesKeyBlob, pEncryptedData, cbEncryptedData);

	std::cerr << "Successfully stored data in vault." << std::endl;
	success = TRUE;

cleanup:
	if (pEncryptedAesKeyBlob != NULL) {
		delete[] pEncryptedAesKeyBlob;
	}

	if (pAesKeyBlob != NULL) {
		delete[] pAesKeyBlob;
	}

	if (pEncryptedData != NULL) {
		delete[] pEncryptedData;
	}
	
	if (pAesIV != NULL) {
		delete[] pAesIV;
	}

	if (pAesKey != NULL) {
		delete[] pAesKey;
	}

	if (hAesKey != NULL) {
		BCryptDestroyKey(hAesKey);
	}

	if (hAesAlg != NULL) {
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	return success;
}

/*
 * Decrypts a vault created by EncryptVault.
 *
 */
BOOLEAN DecryptVault(PBYTE pDataIn, DWORD cbDataIn, PBYTE* ppDataOut, PDWORD pcbDataOut) {
	BOOLEAN success = FALSE;

	BCRYPT_ALG_HANDLE hAesAlg = NULL;
	BCRYPT_KEY_HANDLE hAesKey = NULL;

	PBYTE pAesKeyBlob = NULL;
	DWORD cbAesKeyBlob;

	// Set up required providers.
	if (!CreateAesProvider(&hAesAlg)) {
		goto cleanup;
	}

	// Pull out the header info and do basic validation.
	VAULT_HEADER* pHeader = (VAULT_HEADER*)pDataIn;
	if (pHeader->version != 1) {
		std::cerr << "Wrong vault version: " << pHeader->version << std::endl;
		goto cleanup;
	}

	if (sizeof(VAULT_HEADER) + pHeader->cbAesKey + pHeader->cbData != cbDataIn) {
		std::cerr << "File size mismatch!" << std::endl;
		goto cleanup;
	}

	// Decrypt the (RSA-encrypted) AES key blob.
	if (!DecryptWithTPM(SAMPLE_KEY_ID, pDataIn + sizeof(VAULT_HEADER), pHeader->cbAesKey, &pAesKeyBlob, &cbAesKeyBlob)) {
		goto cleanup;
	}

	std::cerr << "Successfully decrypted AES key using TPM-stored RSA key." << std::endl;

	// Import the now-decrypted AES key.
	NTSTATUS ntStatus = BCryptImportKey(hAesAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hAesKey, NULL, 0, pAesKeyBlob, cbAesKeyBlob - AES_IV_SIZE, 0);
	if (!NT_SUCCESS(ntStatus)) {
		std::cerr << "Error importing decrypted AES key: " << std::hex << ntStatus << std::endl;
		goto cleanup;
	}

	std::cerr << "Successfully loaded AES key." << std::endl;

	// Use that AES key to decrypt the main data. Note that the IV is the last 16 bytes of teh 
	PBYTE pIV = pAesKeyBlob + cbAesKeyBlob - AES_IV_SIZE;
	PBYTE pCiphertext = pDataIn + sizeof(VAULT_HEADER) + pHeader->cbAesKey;
	if (!DecryptWithAES(hAesKey, pIV, AES_IV_SIZE, pCiphertext, pHeader->cbData, ppDataOut, pcbDataOut)) {
		goto cleanup;
	}

	std::cerr << "Successfully decrypted data from vault." << std::endl;

	success = TRUE;

cleanup:
	if (pAesKeyBlob != NULL) {
		delete[] pAesKeyBlob;
	}

	if (hAesKey != NULL) {
		BCryptDestroyKey(hAesKey);
	}

	if (hAesAlg != NULL) {
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	}

	return success;
}


/*
 * Convenience method to load all data from a file to a byte buffer.
 */
BOOLEAN ReadFromFile(LPCSTR path, PBYTE* ppData, PDWORD pcbData) {
	BOOLEAN success = FALSE;

	// Get a handle to the file.
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Error opening file: " << std::hex << GetLastError() << std::endl;
		return FALSE;
	}

	// Determine how large the file is.
	*pcbData = GetFileSize(hFile, NULL);
	if (*pcbData == INVALID_FILE_SIZE) {
		std::cerr << "Error getting file size: " << GetLastError() << std::endl;
		goto cleanup;
	}

	// Allocate a buffer for the file's data, then read it all in.
	*ppData = new BYTE[*pcbData];

	DWORD dwRead;
	if (!ReadFile(hFile, *ppData, *pcbData, &dwRead, NULL)) {
		std::cerr << "Error reading from file: " << std::hex << GetLastError() << std::endl;
		goto cleanup;
	}

	success = TRUE;

cleanup:
	CloseHandle(hFile);

	return success;
}

/*
 * Convenience method to write a byte buffer to a file.
 */
void WriteToFile(LPCSTR path, PBYTE pData, DWORD cbData) {
	// Open (or empty) the specified file.
	HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Error opening file: " << std::hex << GetLastError() << std::endl;
		return;
	}

	// Write all the data to the file.
	DWORD dwWritten;
	if (!WriteFile(hFile, pData, cbData, &dwWritten, NULL)) {
		std::cerr << "Error writing to file: " << std::hex << GetLastError() << std::endl;
 	}

	CloseHandle(hFile);
}

int main(int argc, char** argv)
{
	if (argc < 3) {
		std::cerr << "Usage: " << argv[0] << " (e|d) <input file> [<output file>]" << std::endl;
		return -1;
	}

	PBYTE pInput = NULL;
	DWORD cbInput;

	PBYTE pOutput = NULL;
	DWORD cbOutput;

	if (!ReadFromFile(argv[2], &pInput, &cbInput)) {
		goto cleanup;
	}

	if (strncmp(argv[1], "e", 1) == 0) {
		if (!EncryptVault(pInput, cbInput, &pOutput, &cbOutput)) {
			goto cleanup;
		}
	}
	else if (strncmp(argv[1], "d", 1) == 0) {
		if (!DecryptVault(pInput, cbInput, &pOutput, &cbOutput)) {
			goto cleanup;
		}
	}

	if (argc == 4) {
		WriteToFile(argv[3], pOutput, cbOutput);
	}
	else {
		for (size_t i = 0; i < cbOutput; ++i) {
			printf("%c", pOutput[i]);
		}
	}

cleanup:
	if (pInput != NULL) {
		delete[] pInput;
	}

	if (pOutput != NULL) {
		delete[] pOutput;
	}

    return 0;
}
