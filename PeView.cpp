// PeView.cpp : �������̨Ӧ�ó������ڵ㡣
//
// ԭ������ʣ�https://www.cnblogs.com/LyShark/p/11748296.html

#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <Imagehlp.H>
#pragma comment(lib,"Imagehlp.lib")

// ���ļ�ӳ�䵽�ڴ�
HANDLE OpenPeByFileName(LPTSTR FileName)
{
	LPTSTR peFile = FileName;
	HANDLE hFile, hMapFile, lpMapAddress = NULL;
	DWORD dwFileSize = 0;

	hFile = CreateFile(peFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	dwFileSize = GetFileSize(hFile, NULL);
	hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, dwFileSize, NULL);
	lpMapAddress = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, dwFileSize);
	if (lpMapAddress != NULL)
		return lpMapAddress;
}

// ���DOSͷ��
void DisplayDOSHeadInfo(HANDLE ImageBase)
{
	PIMAGE_DOS_HEADER pDosHead = NULL;
	pDosHead = (PIMAGE_DOS_HEADER)ImageBase;

	printf("DOSͷ��        %x\n", pDosHead->e_magic);
	printf("�ļ���ַ��     %x\n", pDosHead->e_lfarlc);
	printf("PE�ṹƫ�ƣ�   %x\n", pDosHead->e_lfanew);
}

// �ж��ǲ���PE�ļ�
BOOL IsPEFile(HANDLE ImageBase)
{
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	if (ImageBase == NULL){ return FALSE; }
	pDosHead = (PIMAGE_DOS_HEADER)ImageBase;
	if (IMAGE_DOS_SIGNATURE != pDosHead->e_magic){ return FALSE; }
	pNtHead = (PIMAGE_NT_HEADERS)((DWORD)pDosHead + pDosHead->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pNtHead->Signature){ return FALSE; }
	return TRUE;
}

// �õ�PE�е�NTͷ��
PIMAGE_NT_HEADERS GetNtHead(HANDLE ImageBase)
{
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	pDosHead = (PIMAGE_DOS_HEADER)ImageBase;
	pNtHead = (PIMAGE_NT_HEADERS)((DWORD)pDosHead + pDosHead->e_lfanew);
	return pNtHead;
}

// �õ��ļ�ͷ
void DisplayFileHeaderInfo(HANDLE ImageBase)
{
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	pNtHead = GetNtHead(ImageBase);
	pFileHead = &pNtHead->FileHeader;
	printf("����ƽ̨:     %x\n", pFileHead->Machine);
	printf("������Ŀ:     %x\n", pFileHead->NumberOfSections);
	printf("ʱ����:     %x\n", pFileHead->TimeDateStamp);
	printf("��ѡͷ��С    %x\n", pFileHead->SizeOfOptionalHeader);
	printf("�ļ�����:     %x\n", pFileHead->Characteristics);
}

// ��ȡOptionalHeader�ṹ
void DisplayOptionalHeaderInfo(HANDLE ImageBase)
{
	PIMAGE_NT_HEADERS pNtHead = NULL;
	pNtHead = GetNtHead(ImageBase);
	printf("��ڵ㣺        %x\n", pNtHead->OptionalHeader.AddressOfEntryPoint);
	printf("�����ַ��      %x\n", pNtHead->OptionalHeader.ImageBase);
	printf("�����С��      %x\n", pNtHead->OptionalHeader.SizeOfImage);
	printf("�����ַ��      %x\n", pNtHead->OptionalHeader.BaseOfCode);
	printf("������룺      %x\n", pNtHead->OptionalHeader.SectionAlignment);
	printf("�ļ�����룺    %x\n", pNtHead->OptionalHeader.FileAlignment);
	printf("��ϵͳ��        %x\n", pNtHead->OptionalHeader.Subsystem);
	printf("������Ŀ��      %x\n", pNtHead->FileHeader.NumberOfSections);
	printf("ʱ�����ڱ�־��  %x\n", pNtHead->FileHeader.TimeDateStamp);
	printf("�ײ���С��      %x\n", pNtHead->OptionalHeader.SizeOfHeaders);
	printf("����ֵ��        %x\n", pNtHead->FileHeader.Characteristics);
	printf("У��ͣ�        %x\n", pNtHead->OptionalHeader.CheckSum);
	printf("��ѡͷ����С��  %x\n", pNtHead->FileHeader.SizeOfOptionalHeader);
	printf("RVA ������С��  %x\n", pNtHead->OptionalHeader.NumberOfRvaAndSizes);
}

// �õ��ڱ�
void DisplaySectionHeaderInfo(HANDLE ImageBase)
{
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;
	DWORD NumberOfSectinsCount = 0;
	pNtHead = GetNtHead(ImageBase);
	pSection = IMAGE_FIRST_SECTION(pNtHead);
	pFileHead = &pNtHead->FileHeader;

	NumberOfSectinsCount = pFileHead->NumberOfSections;        // �����������
	DWORD *difA = NULL;   // �����ַ��ͷ
	DWORD *difS = NULL;   // ���ƫ��(���ڱ���)
	difA = (DWORD *)malloc(NumberOfSectinsCount*sizeof(DWORD));
	difS = (DWORD *)malloc(NumberOfSectinsCount*sizeof(DWORD));

	printf("�������� ���ƫ��\t�����С\tRaw����ָ��\tRaw���ݴ�С\t��������\n");
	for (int temp = 0; temp<NumberOfSectinsCount; temp++, pSection++)
	{
		printf("%s\t 0x%.8X \t 0x%.8X \t 0x%.8X \t 0x%.8X \t 0x%.8X\n",
			pSection->Name, pSection->VirtualAddress, pSection->Misc.VirtualSize,
			pSection->PointerToRawData, pSection->SizeOfRawData, pSection->Characteristics);
		difA[temp] = pSection->VirtualAddress;
		difS[temp] = pSection->VirtualAddress - pSection->PointerToRawData;
	}
}

// �õ������
void DisplayImportTable(HANDLE ImageBase)
{
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pInput = NULL;
	PIMAGE_THUNK_DATA _pThunk = NULL;
	DWORD dwThunk = NULL;
	USHORT Hint;

	pDosHead = (PIMAGE_DOS_HEADER)ImageBase;
	pNtHead = GetNtHead(ImageBase);

	if (pNtHead->OptionalHeader.DataDirectory[1].VirtualAddress == 0){ return; }  // ��ȡ�����RVA
	pInput = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, pNtHead->OptionalHeader.DataDirectory[1].VirtualAddress, NULL);
	for (; pInput->Name != NULL;)
	{
		char *szFunctionModule = (PSTR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (ULONG)pInput->Name, NULL);  // ������ģ������
		if (pInput->OriginalFirstThunk != 0)
		{
			dwThunk = pInput->OriginalFirstThunk;
			_pThunk = (PIMAGE_THUNK_DATA)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (ULONG)pInput->OriginalFirstThunk, NULL);
		}
		else
		{
			dwThunk = pInput->FirstThunk;
			_pThunk = (PIMAGE_THUNK_DATA)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (ULONG)pInput->FirstThunk, NULL);
		}
		for (; _pThunk->u1.AddressOfData != NULL;)
		{
			char *szFunction = (PSTR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (ULONG)(((PIMAGE_IMPORT_BY_NAME)_pThunk->u1.AddressOfData)->Name), 0);
			if (szFunction != NULL)
				memcpy(&Hint, szFunction - 2, 2);
			else
				Hint = -1;
			printf("%0.4x\t%0.8x\t%s\t %s\n", Hint, dwThunk, szFunctionModule, szFunction);
			dwThunk += 8;  // 32λ=4 64λ=8
			_pThunk++;
		}
		pInput++;
	}
}

// �õ�������
VOID DisplayExportTable(HANDLE ImageBase)
{
	//PIMAGE_NT_HEADERS pNtHead;
	//PIMAGE_DOS_HEADER pDosHead;
	PIMAGE_EXPORT_DIRECTORY pExport;
	// char *filedata;
	// filedata = OpenPeByFileName((LPTSTR)filename);
	//pDosHead = (PIMAGE_DOS_HEADER)filedata;
	//pNtHead = (PIMAGE_NT_HEADERS)(filedata + pDosHead->e_lfanew);
	//if (pNtHead->Signature != 0x00004550){ return; }        // ��ЧPE�ļ�
	//if (pNtHead->OptionalHeader.Magic != 0x20b){return;}  // ����64λPE


	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	//PIMAGE_IMPORT_DESCRIPTOR pInput = NULL;
	PIMAGE_THUNK_DATA _pThunk = NULL;
	DWORD dwThunk = NULL;
	USHORT Hint;

	pDosHead = (PIMAGE_DOS_HEADER)ImageBase;
	pNtHead = GetNtHead(ImageBase);

	pExport = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, pNtHead->OptionalHeader.DataDirectory[0].VirtualAddress, NULL);
	DWORD i = 0;
	DWORD NumberOfNames = pExport->NumberOfNames;
	ULONGLONG **ppdwNames = (ULONGLONG **)pExport->AddressOfNames;
	ppdwNames = (PULONGLONG*)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (ULONG)ppdwNames, NULL);
	ULONGLONG **ppdwAddr = (ULONGLONG **)pExport->AddressOfFunctions;
	ppdwAddr = (PULONGLONG*)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (DWORD)ppdwAddr, NULL);
	ULONGLONG *ppdwOrdin = (ULONGLONG*)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (DWORD)pExport->AddressOfNameOrdinals, NULL);
	char* szFunction = (PSTR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (ULONG)*ppdwNames, NULL);
	for (i = 0; i<NumberOfNames; i++)
	{
		printf("%0.8x\t%s\n", *ppdwAddr, szFunction);
		szFunction = szFunction + strlen(szFunction) + 1;
		ppdwAddr++;
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE lpMapAddress = NULL;
	lpMapAddress = OpenPeByFileName(L"c://win32.exe");

	DisplayDOSHeadInfo(lpMapAddress);

	BOOL ispe = IsPEFile(lpMapAddress);
	printf("�Ƿ���PE: %d \n", ispe);


	PIMAGE_NT_HEADERS nthead = GetNtHead(lpMapAddress);
	printf("NTͷ��: 0x%x \n", nthead);

	DisplayFileHeaderInfo(lpMapAddress);

	DisplayOptionalHeaderInfo(lpMapAddress);

	DisplaySectionHeaderInfo(lpMapAddress);

	DisplayImportTable(lpMapAddress);

	DisplayExportTable(lpMapAddress);


	getchar();
	return 0;
}

