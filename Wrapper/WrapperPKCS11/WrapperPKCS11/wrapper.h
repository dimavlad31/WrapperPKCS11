#ifndef WRAPPER_H
#define WRAPPER_H

#include <windows.h>
#include "pkcs11.h"

#ifdef WRAPPER_EXPORTS
#define WRAPPER_API __declspec(dllexport)
#else
#define WRAPPER_API __declspec(dllimport)
#endif

WRAPPER_API CK_RV C_Initialize(void* pInitArgs);
WRAPPER_API CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
WRAPPER_API CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, void* pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
WRAPPER_API CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
WRAPPER_API CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
WRAPPER_API CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
WRAPPER_API CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
WRAPPER_API CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
WRAPPER_API CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
WRAPPER_API CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
WRAPPER_API CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);


#endif // WRAPPER_H
