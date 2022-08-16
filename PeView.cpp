// PeView.cpp : 定义控制台应用程序的入口点。
//
// 原理请访问：https://www.cnblogs.com/LyShark/p/11748296.html

#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <Imagehlp.H>
#pragma comment(lib,"Imagehlp.lib")

// 打开文件映射到内存
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

// 输出DOS头部
void DisplayDOSHeadInfo(HANDLE ImageBase)
{
	PIMAGE_DOS_HEADER pDosHead = NULL;
	pDosHead = (PIMAGE_DOS_HEADER)ImageBase;

	printf("DOS头：        %x\n", pDosHead->e_magic);
	printf("文件地址：     %x\n", pDosHead->e_lfarlc);
	printf("PE结构偏移：   %x\n", pDosHead->e_lfanew);
}

// 判断是不是PE文件
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

// 得到PE中的NT头部
PIMAGE_NT_HEADERS GetNtHead(HANDLE ImageBase)
{
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	pDosHead = (PIMAGE_DOS_HEADER)ImageBase;
	pNtHead = (PIMAGE_NT_HEADERS)((DWORD)pDosHead + pDosHead->e_lfanew);
	return pNtHead;
}

// 得到文件头
void DisplayFileHeaderInfo(HANDLE ImageBase)
{
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	pNtHead = GetNtHead(ImageBase);
	pFileHead = &pNtHead->FileHeader;
	printf("运行平台:     %x\n", pFileHead->Machine);
	printf("节区数目:     %x\n", pFileHead->NumberOfSections);
	printf("时间标记:     %x\n", pFileHead->TimeDateStamp);
	printf("可选头大小    %x\n", pFileHead->SizeOfOptionalHeader);
	printf("文件特性:     %x\n", pFileHead->Characteristics);
}

// 读取OptionalHeader结构
void DisplayOptionalHeaderInfo(HANDLE ImageBase)
{
	PIMAGE_NT_HEADERS pNtHead = NULL;
	pNtHead = GetNtHead(ImageBase);
	printf("入口点：        %x\n", pNtHead->OptionalHeader.AddressOfEntryPoint);
	printf("镜像基址：      %x\n", pNtHead->OptionalHeader.ImageBase);
	printf("镜像大小：      %x\n", pNtHead->OptionalHeader.SizeOfImage);
	printf("代码基址：      %x\n", pNtHead->OptionalHeader.BaseOfCode);
	printf("区块对齐：      %x\n", pNtHead->OptionalHeader.SectionAlignment);
	printf("文件块对齐：    %x\n", pNtHead->OptionalHeader.FileAlignment);
	printf("子系统：        %x\n", pNtHead->OptionalHeader.Subsystem);
	printf("区段数目：      %x\n", pNtHead->FileHeader.NumberOfSections);
	printf("时间日期标志：  %x\n", pNtHead->FileHeader.TimeDateStamp);
	printf("首部大小：      %x\n", pNtHead->OptionalHeader.SizeOfHeaders);
	printf("特征值：        %x\n", pNtHead->FileHeader.Characteristics);
	printf("校验和：        %x\n", pNtHead->OptionalHeader.CheckSum);
	printf("可选头部大小：  %x\n", pNtHead->FileHeader.SizeOfOptionalHeader);
	printf("RVA 数及大小：  %x\n", pNtHead->OptionalHeader.NumberOfRvaAndSizes);
}

// 得到节表
void DisplaySectionHeaderInfo(HANDLE ImageBase)
{
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;
	DWORD NumberOfSectinsCount = 0;
	pNtHead = GetNtHead(ImageBase);
	pSection = IMAGE_FIRST_SECTION(pNtHead);
	pFileHead = &pNtHead->FileHeader;

	NumberOfSectinsCount = pFileHead->NumberOfSections;        // 获得区段数量
	DWORD *difA = NULL;   // 虚拟地址开头
	DWORD *difS = NULL;   // 相对偏移(用于遍历)
	difA = (DWORD *)malloc(NumberOfSectinsCount*sizeof(DWORD));
	difS = (DWORD *)malloc(NumberOfSectinsCount*sizeof(DWORD));

	printf("节区名称 相对偏移\t虚拟大小\tRaw数据指针\tRaw数据大小\t节区属性\n");
	for (int temp = 0; temp<NumberOfSectinsCount; temp++, pSection++)
	{
		printf("%s\t 0x%.8X \t 0x%.8X \t 0x%.8X \t 0x%.8X \t 0x%.8X\n",
			pSection->Name, pSection->VirtualAddress, pSection->Misc.VirtualSize,
			pSection->PointerToRawData, pSection->SizeOfRawData, pSection->Characteristics);
		difA[temp] = pSection->VirtualAddress;
		difS[temp] = pSection->VirtualAddress - pSection->PointerToRawData;
	}
}

// 得到导入表
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

	if (pNtHead->OptionalHeader.DataDirectory[1].VirtualAddress == 0){ return; }  // 读取导入表RVA
	pInput = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, pNtHead->OptionalHeader.DataDirectory[1].VirtualAddress, NULL);
	for (; pInput->Name != NULL;)
	{
		char *szFunctionModule = (PSTR)ImageRvaToVa((PIMAGE_NT_HEADERS)pNtHead, pDosHead, (ULONG)pInput->Name, NULL);  // 遍历出模块名称
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
			dwThunk += 8;  // 32位=4 64位=8
			_pThunk++;
		}
		pInput++;
	}
}

// 得到导出表
VOID DisplayExportTable(HANDLE ImageBase)
{
	//PIMAGE_NT_HEADERS pNtHead;
	//PIMAGE_DOS_HEADER pDosHead;
	PIMAGE_EXPORT_DIRECTORY pExport;
	// char *filedata;
	// filedata = OpenPeByFileName((LPTSTR)filename);
	//pDosHead = (PIMAGE_DOS_HEADER)filedata;
	//pNtHead = (PIMAGE_NT_HEADERS)(filedata + pDosHead->e_lfanew);
	//if (pNtHead->Signature != 0x00004550){ return; }        // 无效PE文件
	//if (pNtHead->OptionalHeader.Magic != 0x20b){return;}  // 不是64位PE


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
	printf("是否是PE: %d \n", ispe);


	PIMAGE_NT_HEADERS nthead = GetNtHead(lpMapAddress);
	printf("NT头部: 0x%x \n", nthead);

	DisplayFileHeaderInfo(lpMapAddress);

	DisplayOptionalHeaderInfo(lpMapAddress);

	DisplaySectionHeaderInfo(lpMapAddress);

	DisplayImportTable(lpMapAddress);

	DisplayExportTable(lpMapAddress);


	getchar();
	return 0;
}

