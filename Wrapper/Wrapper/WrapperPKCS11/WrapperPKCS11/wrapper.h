#ifndef WRAPPER_H
#define WRAPPER_H

#include <windows.h>
#include "pkcs11.h"

#ifdef WRAPPER_EXPORTS
#define WRAPPER_API __declspec(dllexport)
#else
#define WRAPPER_API __declspec(dllimport)
#endif

WRAPPER_API CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
WRAPPER_API CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
WRAPPER_API CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
WRAPPER_API CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
#endif // WRAPPER_H
