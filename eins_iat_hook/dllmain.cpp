// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

typedef HWND(WINAPI *__PFNCREATEWINDOWEXW)(
	DWORD     dwExStyle,
	LPCWSTR   lpClassName,
	LPCWSTR   lpWindowName,
	DWORD     dwStyle,
	int       X,
	int       Y,
	int       nWidth,
	int       nHeight,
	HWND      hWndParent,
	HMENU     hMenu,
	HINSTANCE hInstance,
	LPVOID    lpParam
	);

__PFNCREATEWINDOWEXW org_create_window_ex_w = NULL;

HWND WINAPI CreateWindowExWFilter(
	DWORD     dwExStyle,
	LPCWSTR   lpClassName,
	LPCWSTR   lpWindowName,
	DWORD     dwStyle,
	int       X,
	int       Y,
	int       nWidth,
	int       nHeight,
	HWND      hWndParent,
	HMENU     hMenu,
	HINSTANCE hInstance,
	LPVOID    lpParam
)
{
	OutputDebugString(L"CreateWindowExWFilter");
	return org_create_window_ex_w(dwExStyle, lpClassName, lpWindowName, dwStyle,
		X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

typedef int (WINAPI *__PFNMESSAGEBOXW)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType
	);

__PFNMESSAGEBOXW org_message_box_w = NULL;

int WINAPI MessageBoxWFilter(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType
)
{
	OutputDebugString(L"MessageBoxWFilter");
	return org_message_box_w(hWnd, lpText, lpCaption, uType);
}

template <typename T>
BOOL IAT_Hook(LPVOID lpBaseAddress, const char *apiName, T new_fn, T &org_fn)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	DWORD dwImpotStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;

	pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBaseAddress + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	optionalHeader = pNtHeader->OptionalHeader;
	if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
		optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return FALSE;

	importDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	dwImpotStartRVA = importDirectory.VirtualAddress;
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpBaseAddress + importDirectory.VirtualAddress);
	if (pImportDescriptor == NULL)
		return FALSE;

	DWORD dwIndex = -1;
	while (pImportDescriptor[++dwIndex].Characteristics != 0)
	{
		PIMAGE_THUNK_DATA pINT;
		PIMAGE_THUNK_DATA pIAT;
		PIMAGE_IMPORT_BY_NAME pNameData;
		DWORD nFunctions = 0;
		DWORD nOrdinalFunctions = 0;

		char *dllName = (char *)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].Name);

		pINT = (PIMAGE_THUNK_DATA)(pImportDescriptor[dwIndex].OriginalFirstThunk);
		pIAT = (PIMAGE_THUNK_DATA)(pImportDescriptor[dwIndex].FirstThunk);
		if (pINT == NULL)
			return FALSE;

		if (pIAT == NULL)
			return FALSE;

		pINT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].OriginalFirstThunk);
		pIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].FirstThunk);
		if (pINT == NULL)
			return FALSE;

		if (pIAT == NULL)
			return FALSE;

		while (pINT->u1.AddressOfData != 0)
		{
			if (!(pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				pNameData = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData);
				pNameData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBaseAddress + (DWORD)pNameData);
				if (strcmp(apiName, (const char *)pNameData->Name) == 0)
				{
					DWORD dwOldProtect, temp;
					org_fn = (T)pIAT->u1.Function;

					if (!VirtualProtect(&pIAT->u1.Function, sizeof(LPVOID), PAGE_READWRITE, &dwOldProtect))
					{
						return FALSE;
					}
					pIAT->u1.Function = (DWORD_PTR)new_fn;
					if (!VirtualProtect(&pIAT->u1.Function, sizeof(LPVOID), dwOldProtect, &temp))
					{
						return FALSE;
					}
				}
			}
			else
			{
				nOrdinalFunctions++;
			}

			pIAT++;
			pINT++;
			nFunctions++;
		}
	}

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	LPVOID base_addr = GetModuleHandle(NULL);

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		IAT_Hook<__PFNCREATEWINDOWEXW>(
			base_addr, "CreateWindowExW", CreateWindowExWFilter, org_create_window_ex_w);
		IAT_Hook<__PFNMESSAGEBOXW>(
			base_addr, "MessageBoxW", MessageBoxWFilter, org_message_box_w);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
