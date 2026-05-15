#include "pe.h"
#include "resource.h"
#include <combaseapi.h>
#include <shtypes.h>
#include <shobjidl_core.h>
#include <time.h>
#include <stdio.h>
#include <vector>

// 定义 [标志字] 配置表
const CHARACTERISTIC_INFO g_CharacteristicsFlags[] = {
	{ IMAGE_FILE_RELOCS_STRIPPED, L"重定位信息已剥离,必须加载于ImageBase" },
	{ IMAGE_FILE_EXECUTABLE_IMAGE, L"文件是可执行的" },
	{ IMAGE_FILE_LINE_NUMS_STRIPPED, L"COFF 行号信息已从文件中移除（已过时）"},
	{ IMAGE_FILE_LOCAL_SYMS_STRIPPED, L"COFF 本地符号表信息已从文件中移除（已过时）"},
	{ IMAGE_FILE_AGGRESIVE_WS_TRIM, L"操作系统应积极修剪该进程的工作集。此标志已过时，应为0"},
	{ IMAGE_FILE_LARGE_ADDRESS_AWARE, L"应用程序能够处理大于2GB的虚拟地址空间。在64位系统上32程序可获得完整的4GB虚拟地址空间"},
	{ IMAGE_FILE_BYTES_REVERSED_LO, L"文件使用小端字节序。此标志已过时，应为0"},
	{ IMAGE_FILE_32BIT_MACHINE, L"文件基于32位计算机架构"},
	{ IMAGE_FILE_DEBUG_STRIPPED, L"调试信息已从文件中移除，并可能存储在单独的.dbg文件中"},
	{ IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, L"如果文件位于可移动介质（如光盘），应先将其复制到交换文件再运行"},
	{ IMAGE_FILE_NET_RUN_FROM_SWAP, L"如果文件位于网络介质，应先将其复制到交换文件再运行"},
	{ IMAGE_FILE_SYSTEM, L"文件是系统文件（如驱动程序），不能直接运行" },
	{ IMAGE_FILE_DLL, L"文件是一个动态链接库（DLL），不能直接运行" },
	{ IMAGE_FILE_UP_SYSTEM_ONLY, L"文件只能在单处理器（UP）系统上运行" },
	{ IMAGE_FILE_BYTES_REVERSED_HI, L"文件使用大端字节序。此标志已过时，应为0" }
};
const int g_nCharacteristicsFlagsCount = ARRAYSIZE(g_CharacteristicsFlags);

// 定义 [特征值] 配置表
const CHARACTERISTIC_INFO g_DllCharacteristicsFlags[] = {
	{0}, // 保留
	{0},
	{0},
	{0},
	{ IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,		  L"具有 64 位地址空间的 ASLR"},
	{ IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,          L"支持 ASLR（动态基址）" },
	{ IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,       L"强制代码完整性检查" },
	{ IMAGE_DLLCHARACTERISTICS_NX_COMPAT,             L"与数据执行保护（DEP/NX）兼容" },
	{ IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,          L"不进行隔离，但支持隔离感知" },
	{ IMAGE_DLLCHARACTERISTICS_NO_SEH,                L"不使用结构化异常处理（SEH）不能在此映像中调用任何处理程序" },
	{ IMAGE_DLLCHARACTERISTICS_NO_BIND,               L"不绑定映像（禁止导入绑定）" },
	{ IMAGE_DLLCHARACTERISTICS_APPCONTAINER,          L"需在 AppContainer 中执行" },
	{ IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,            L"WDM 驱动程序" },
	{ IMAGE_DLLCHARACTERISTICS_GUARD_CF,              L"支持控制流防护（CFG）" },
	{ IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, L"支持终端服务器感知" }
};
// 定义数组长度
const int g_nDllCharacteristicsFlagsCount = ARRAYSIZE(g_DllCharacteristicsFlags);

// 机器架构
const Machine_INFO g_Machine_INFO[] = {
	{0x014C, L"Intel i386 或兼容架构，即32位x86程序"},
	{0x8664, L"AMD64(x86 - 64) 架构，即64位程序"},
	{0x01C0, L"ARM 架构"},
	{0xAA64, L"ARM64 架构"},
	{0x0200, L"Intel Itanium 64位架构"},
	{0x01C4, L"ARM Thumb/Thumb-2"},
	{0x0162, L"MIPS R3000"},
	{0x0166, L"MIPS R4000"}
};
const int g_nMachine_INFO = ARRAYSIZE(g_Machine_INFO);

// Magic
const Magic_INFO g_Magic_INFO[] = {
	{0x010B, L"32位PE文件(PE32)"},
	{0x020B, L"64位PE文件(PE32 + )"},
	{0x0107, L"ROM 镜像"}
};
const int g_nMagic_INFO = ARRAYSIZE(g_Magic_INFO);

// Subsystem 
const Subsystem_INFO g_Subsystem_INFO[] = {
	{0, L"未知子系统"},
	{1, L"原生（Native）无需子系统 (设备驱动程序和本机系统进程) "},
	{2, L"Windows GUI-普通窗口程序"},
	{3, L"Windows CUI-控制台(Console)程序"},
	{5, L"OS/2字符模式"},
	{7, L"POSIX 字符模式"},
	{8, L"原生 Win9x 驱动"},
	{9, L"Windows CE"},
	{10, L"EFI 应用程序"},
	{16, L"Windows 启动应用程序"}
};
const int g_nSubsystem_INFO = ARRAYSIZE(g_Subsystem_INFO);

// 节属性字典
const SectionCharac g_SectionCharac[] = {
	{0x00000000, L"保留。"},
	{0x00000001, L"保留。"},
	{0x00000002, L"保留。"},
	{0x00000004, L"保留。"},
	{IMAGE_SCN_TYPE_NO_PAD, L"不应将节填充到下一个边界。此标志已过时，由 IMAGE_SCN_ALIGN_1BYTES 取代。"},
	{0x00000010, L"保留。"},
	{IMAGE_SCN_CNT_CODE, L"节包含可执行代码。"},
	{IMAGE_SCN_CNT_INITIALIZED_DATA, L"节包含初始化数据。"},
	{IMAGE_SCN_CNT_UNINITIALIZED_DATA, L"节包含未初始化数据。"},
	{IMAGE_SCN_LNK_OTHER, L"保留。"}, // 实际注释为保留
	{IMAGE_SCN_LNK_INFO, L"节包含注释或其他信息。它仅对对象文件有效。"},
	{0x00000400, L"保留。"},
	{IMAGE_SCN_LNK_REMOVE, L"节不会成为映像的一部分。它仅对对象文件有效。"},
	{IMAGE_SCN_LNK_COMDAT, L"节包含 COMDAT 数据。它仅对对象文件有效。"},
	{0x00002000, L"保留。"},
	{IMAGE_SCN_NO_DEFER_SPEC_EXC, L"重置本部分的 TLB 条目中处理位的推理异常。"},
	{IMAGE_SCN_GPREL, L"节包含通过全局指针引用的数据。"},
	{0x00010000, L"保留。"},
	{IMAGE_SCN_MEM_PURGEABLE, L"保留。"}, // 宏名存在但文档标记保留
	{IMAGE_SCN_MEM_LOCKED, L"保留。"},
	{IMAGE_SCN_MEM_PRELOAD, L"保留。"},
	// 20(bit[1:20])
	{IMAGE_SCN_ALIGN_1BYTES, L"在 1 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_2BYTES, L"在 2 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_4BYTES, L"在 4 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_8BYTES, L"对齐 8 字节边界上的数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_16BYTES, L"在 16 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_32BYTES, L"在 32 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_64BYTES, L"在 64 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_128BYTES, L"在 128 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_256BYTES, L"在 256 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_512BYTES, L"在 512 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_1024BYTES, L"在 1024 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_2048BYTES, L"在 2048 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_4096BYTES, L"在 4096 字节边界上对齐数据。它仅对对象文件有效。"},
	{IMAGE_SCN_ALIGN_8192BYTES, L"对齐 8192 字节边界上的数据。它仅对对象文件有效。"},
	// 34(bit[21:24])
	{IMAGE_SCN_LNK_NRELOC_OVFL, L"节包含扩展重定位。节的重定位计数超过了节标头中为其保留的 16 位。如果节标题中的 NumberOfRelocations 字段0xffff，则实际重定位计数将存储在第一次重定位的 VirtualAddress 字段中。如果设置了 IMAGE_SCN_LNK_NRELOC_OVFL，并且节中的重定位数少于 0xffff，则为错误。"}, 
	{IMAGE_SCN_MEM_DISCARDABLE, L"可以根据需要丢弃节。"},
	{IMAGE_SCN_MEM_NOT_CACHED, L"无法缓存节。"},
	{IMAGE_SCN_MEM_NOT_PAGED, L"该节不能分页。"},
	{IMAGE_SCN_MEM_SHARED, L"可以在内存中共享节。"},
	{IMAGE_SCN_MEM_EXECUTE, L"节可以作为代码执行。"},
	{IMAGE_SCN_MEM_READ, L"可以读取节。"},
	{IMAGE_SCN_MEM_WRITE, L"可以写入节。"}
	// 42(bit[25:32])
};
const int g_nSectionCharac = ARRAYSIZE(g_SectionCharac);

void ClosePeFile(PPE_CONTEXT pPeCtx) {
	if (pPeCtx->pBase) UnmapViewOfFile(pPeCtx->pBase);
	if (pPeCtx->hMap) CloseHandle(pPeCtx->hMap);
	if (pPeCtx->hFile != INVALID_HANDLE_VALUE) CloseHandle(pPeCtx->hFile);
}

bool OpenPEFile(HWND hdlg, LPWSTR FilePathName, size_t destSize) {
	// 使用新版API —— COM组件
	HRESULT hresult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED); // 初始化COM库
	if (FAILED(hresult)) {
		MessageBoxW(hdlg, L"COM初始化失败", L"CoInitializeEx", MB_OK);
		return FALSE;
	}
	IFileOpenDialog* pFileOpen = NULL; // IFileOpenDialog对象
	// 1. 创建 FileOpenDialog 对象
	hresult = CoCreateInstance(
		CLSID_FileOpenDialog,       // 固定的 CLSID，表示我们要创建“打开文件”对话框
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&pFileOpen)    // 自动获取 IFileOpenDialog 接口
	);
	// 获取到组件接口
	if (SUCCEEDED(hresult)) {
		COMDLG_FILTERSPEC rgSpec[] = { // 过滤器
		{ L"所有 PE 文件 (*.exe;*.dll;*.sys;*.ocx)", L"*.exe;*.dll;*.sys;*.ocx" },
		{ L"EXE 程序 (*.exe)", L"*.exe" },
		{ L"DLL 动态库 (*.dll)", L"*.dll" },
		{ L"所有文件 (*.*)", L"*.*" }
		};

		// 3. 应用过滤器：数量+数组
		pFileOpen->SetFileTypes(ARRAYSIZE(rgSpec), rgSpec);

		// 4. 设置默认选中第 0 个过滤器
		pFileOpen->SetFileTypeIndex(1);

		// 6. 显示对话框！
		// 注意：Show 会阻塞，直到用户点击“打开”或“取消”
		hresult = pFileOpen->Show(hdlg);

		// 如果点击了打开
		if (SUCCEEDED(hresult)) {
			IShellItem* pItem = NULL;
			hresult = pFileOpen->GetResult(&pItem);
			// 成功获取结果
			if (SUCCEEDED(hresult)) {
				PWSTR pszFilePath = NULL;
				// 8. 获取文件系统路径 (SIGDN_FILESYSPATH 表示要完整的盘符路径)
				hresult = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
				if (SUCCEEDED(hresult)) {
					// 要做的事情 —— 外传文件路径
					wcsncpy_s(FilePathName, destSize, pszFilePath, _TRUNCATE);
					CoTaskMemFree(pszFilePath); // 释放路径字符串
				}
				pItem->Release(); // 释放选中结果
			}
		}
		pFileOpen->Release(); // 释放接口
	}
	CoUninitialize(); // 释放COM组件
	return TRUE;
}


HRESULT ParsePeContext(LPCWSTR pszFilePath, PPE_CONTEXT pPeCtx) {
	
	/**
	*	函数目前并不支持PE解析失败自动释放PE映射资源
	*	hFile、hMap、pBase 3个资源不用时必须释放
	*/

	if (!pszFilePath || !pPeCtx) return E_INVALIDARG;
	ZeroMemory(pPeCtx, sizeof(PE_CONTEXT)); // 初始化结构体

	HANDLE hFile = INVALID_HANDLE_VALUE;
	HRESULT hr = E_FAIL;
	HANDLE hMap = NULL;
	LPVOID pBase = NULL;

	// 打开文件获取句柄
	hFile = CreateFileW(pszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD dwLastError = GetLastError();
		WCHAR wszLastError[9] = { '\0' };
		swprintf_s(wszLastError, 9, L"%d", dwLastError);
		MessageBoxW(NULL, wszLastError, L"ParsePeHeader!CreateFileW错误码", MB_OK);
		goto Cleanup;
	}
	
	// 创建文件映射对象
	hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMap) goto Cleanup;

	// 映射到进程内存
	pBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (!pBase) goto Cleanup;

	// 保存句柄
	pPeCtx->hFile = hFile;
	pPeCtx->hMap = hMap;
	pPeCtx->pBase = pBase;
	
	// 解析PE头
	{
		// 保存头指针
		// Dos
		pPeCtx->pDosHeader = (PIMAGE_DOS_HEADER)pBase;
		if (pPeCtx->pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			MessageBoxW(NULL, L"不是标准PE文件格式！", L"ParsePeContext", MB_OK);
			hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
			goto Cleanup;
		}

		// Nt Header
		pPeCtx->pNtHeaders32 = (PIMAGE_NT_HEADERS32)((BYTE*)pBase + pPeCtx->pDosHeader->e_lfanew);
		if (pPeCtx->pNtHeaders32->Signature != IMAGE_NT_SIGNATURE) {
			MessageBoxW(NULL, L"不是标准PE文件格式！", L"ParsePeContext", MB_OK);
			hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
			goto Cleanup;
		}

		// 文件头
		pPeCtx->pFileHeader = &pPeCtx->pNtHeaders32->FileHeader;

		// 判断位数拿不同的 可选头
		// Optional header 第一个字段Magic得偏移永远不会变，从着读取位数
		pPeCtx->Is64Bit = pPeCtx->pNtHeaders32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? TRUE : FALSE;

		if (pPeCtx->Is64Bit) {

			// 64 位
			pPeCtx->pOptHeader64 = (PIMAGE_OPTIONAL_HEADER64) & (pPeCtx->pNtHeaders32->OptionalHeader);
			// 节表
			pPeCtx->pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pPeCtx->pOptHeader64 + pPeCtx->pFileHeader->SizeOfOptionalHeader);
			// 数据目录
			pPeCtx->pDataDirectory = pPeCtx->pOptHeader64->DataDirectory;
			// ImageBase
			pPeCtx->ImageBase = pPeCtx->pOptHeader64->ImageBase;
		}
		else {

			// 32 位
			pPeCtx->pOptHeader32 = (PIMAGE_OPTIONAL_HEADER32) & (pPeCtx->pNtHeaders32->OptionalHeader);
			// 节表
			pPeCtx->pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pPeCtx->pOptHeader32 + pPeCtx->pFileHeader->SizeOfOptionalHeader);
			// 数据目录
			pPeCtx->pDataDirectory = pPeCtx->pOptHeader32->DataDirectory;
			// ImageBase
			pPeCtx->ImageBase = pPeCtx->pOptHeader32->ImageBase;
		}
	} // End PE 解析

	hr = S_OK;

Cleanup:
	return hr;
}


void FillPeHeaderToUi(HWND hPEInfo, PCPE_CONTEXT PeCtx) {

	WCHAR szBuff[32];
	CONST WCHAR HexFormat[] = L"0x%llX";
	CONST WCHAR SizeFormat[] = L"%u";

	PIMAGE_FILE_HEADER pFileHeader = PeCtx->pFileHeader;
	PIMAGE_OPTIONAL_HEADER32  pOptHeader32 = PeCtx->pOptHeader32;
	PIMAGE_OPTIONAL_HEADER64  pOptHeader64 = PeCtx->pOptHeader64;

	bool is64 = PeCtx->Is64Bit;
	
	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->AddressOfEntryPoint : pOptHeader32->AddressOfEntryPoint);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_OEP, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->ImageBase : pOptHeader32->ImageBase);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_IMAGEBASE, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->SizeOfImage : pOptHeader32->SizeOfImage);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_IMAGESIZE, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->BaseOfCode : pOptHeader32->BaseOfCode);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_CODEBASE, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? 0 : pOptHeader32->BaseOfData);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_DATABASE, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->SectionAlignment : pOptHeader32->SectionAlignment);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_SECTIONALIGNMENT, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->FileAlignment : pOptHeader32->FileAlignment);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_FILEALIGNMENT, (LPCWSTR)szBuff);

	swprintf_s(szBuff, SizeFormat, (ULONGLONG)is64 ? pOptHeader64->Subsystem : pOptHeader32->Subsystem);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_SUBSYSTEM, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->SizeOfHeaders : pOptHeader32->SizeOfHeaders);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_SIZEOFHEADERS, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->CheckSum : pOptHeader32->CheckSum);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_CHECKSUM, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->DllCharacteristics : pOptHeader32->DllCharacteristics);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_DLLCHARACTERISTICS, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (ULONGLONG)is64 ? pOptHeader64->Magic : pOptHeader32->Magic);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_MAGIC, (LPCWSTR)szBuff);

	swprintf_s(szBuff, SizeFormat, (ULONGLONG)is64 ? pOptHeader64->NumberOfRvaAndSizes : pOptHeader32->NumberOfRvaAndSizes);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_DIRECTORYCOUNT, (LPCWSTR)szBuff);


	// 与位数无关字段
	swprintf_s(szBuff, HexFormat, (WORD)pFileHeader->Characteristics);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_CHARACTERISTICS, (LPCWSTR)szBuff);

	swprintf_s(szBuff, SizeFormat, (WORD)pFileHeader->NumberOfSections);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_SECTIONCOUNT, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (DWORD)pFileHeader->TimeDateStamp);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_TIMEDATASTAMP, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (WORD)pFileHeader->Machine);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_MECHINEARCH, (LPCWSTR)szBuff);

	swprintf_s(szBuff, HexFormat, (WORD)pFileHeader->SizeOfOptionalHeader);
	SetDlgItemTextW(hPEInfo, IDC_EDIT_OPTIONALHEADERSIZE, (LPCWSTR)szBuff);

}

// 填充 Section Dialog
void FillSectionDialog(HWND hSectionDlg, PCPE_CONTEXT PCPeCtx) {
	LVITEMW lvi;
	memset(&lvi, 0, sizeof(LVITEMW));
	lvi.mask = LVIF_TEXT;

	CHAR szName[9];
	WCHAR wszSectionName[9];
	WCHAR wArray[11];   // pszText公用数组
	CONST WCHAR Format[] = L"0x%X";

	HWND pListSection = GetDlgItem(hSectionDlg, IDC_LIST_SECTION);

	PIMAGE_FILE_HEADER pFileHeader = PCPeCtx->pFileHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = PCPeCtx->pSectionHeader;

	// 节表数组大小
	int SectionSize = (int)pFileHeader->NumberOfSections;

	// 填充
	for (int i = 0;i < SectionSize; i++) {

		// Name
		memcpy(szName, pSectionHeader[i].Name, 8);
		szName[8] = '\0';
		MultiByteToWideChar(CP_ACP, 0, szName, -1, wszSectionName, _countof(wszSectionName)); // CHAR --> WCHAR

		lvi.iItem = i;
		lvi.pszText = wszSectionName;
		lvi.iSubItem = 0;
		SendMessageW(pListSection, LVM_INSERTITEMW, 0, (LPARAM)&lvi);


		// 文件偏移
		swprintf_s(wArray, Format, pSectionHeader[i].PointerToRawData);
		lvi.pszText = wArray;
		lvi.iSubItem = 1;
		SendMessageW(pListSection, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);

		// 文件大小
		swprintf_s(wArray, Format, pSectionHeader[i].SizeOfRawData);
		lvi.pszText = wArray;
		lvi.iSubItem = 2;
		SendMessageW(pListSection, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);

		// 内存偏移
		swprintf_s(wArray, Format, pSectionHeader[i].VirtualAddress);
		lvi.pszText = wArray;
		lvi.iSubItem = 3;
		SendMessageW(pListSection, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);

		// 内存大小
		swprintf_s(wArray, Format, pSectionHeader[i].Misc.VirtualSize);
		lvi.pszText = wArray;
		lvi.iSubItem = 4;
		SendMessageW(pListSection, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);

		// 节段属性
		swprintf_s(wArray, Format, pSectionHeader[i].Characteristics);
		lvi.iSubItem = 5;
		SendMessageW(pListSection, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);
	}

}


void OpenPEInfo(HINSTANCE hpexplore, HWND hdlg, WNDPROC PEInfoDialogProc) {
	// 拿到文件路径
	WCHAR FilePathName[260];
	OpenPEFile(hdlg, FilePathName, _countof(FilePathName));
	// 解析 PE 文件
	PE_CONTEXT PeCtx;
	HRESULT hr;
	hr = ParsePeContext(FilePathName, &PeCtx);
	// 解析成功创建 PE Info窗口
	if (SUCCEEDED(hr)) {
		//DialogBoxW(hpexplore, (LPCWSTR)IDD_DIALOG_PEINFO, hdlg, PEInfoDialogProc);
		// DialogBoxParamW 允许我们自定义一个参数传递到新的对话框 —— 传递PeCtx
		DialogBoxParamW(hpexplore, (LPCWSTR)IDD_DIALOG_PEINFO, hdlg, PEInfoDialogProc, (LPARAM)&PeCtx);
	}
	else if (FAILED(hr)) {
		ClosePeFile(&PeCtx);
	}
}

void InitCharacDialog(HWND hCharacDetail) {
	LV_COLUMNW lvc;
	HWND hListChara = NULL;

	memset(&lvc, 0, sizeof(LV_COLUMNW));
	hListChara = GetDlgItem(hCharacDetail, IDC_LIST_CHARACTERISTIC_DEATIL);

	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_LEFT;

	lvc.pszText = (LPWSTR)L"已置位";
	lvc.cx = 70;
	SendMessageW(hListChara, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"比特位含义";
	lvc.cx = 700;
	SendMessageW(hListChara, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);
}

void FillCharacToUI(HWND hCharacDetail, const int CharacteristicsFlagsCount, WORD wAvtiveFlags, PCCHARACTERISTIC_INFO pcCharacInfoArray) {
	LVITEMW lvi;
	memset(&lvi, 0, sizeof(LVITEMW));
	lvi.mask = LVIF_TEXT;

	bool IsSet = FALSE;

	WCHAR bit[6];
	
	HWND hListCharac = NULL;

	int nItemIndex = 0;
	// 解析
	hListCharac = GetDlgItem(hCharacDetail, IDC_LIST_CHARACTERISTIC_DEATIL);

	for (int i = 0;i < CharacteristicsFlagsCount; i++) {
		IsSet = pcCharacInfoArray[i].dwValue & (DWORD)wAvtiveFlags;
		if (IsSet) {
			// 位
			swprintf_s(bit, 4, L"%u", i+1);

			lvi.iItem = nItemIndex;
			lvi.iSubItem = 0;
			lvi.pszText = bit;
			SendMessageW(hListCharac, LVM_INSERTITEMW, 0, (LPARAM)&lvi);
			
			// 含义
			lvi.iItem = nItemIndex;
			lvi.pszText = (LPWSTR)pcCharacInfoArray[i].pszDesc;
			lvi.iSubItem = 1;
			SendMessageW(hListCharac, LVM_SETITEMTEXTW, nItemIndex, (LPARAM)&lvi);

			nItemIndex++;
		}
	}
	// 自动宽度
	SendMessageW(hListCharac, LVM_SETCOLUMNWIDTH, 1, LVSCW_AUTOSIZE);
}

void FillPEInfoDetailUI(HWND hPEInfoDetail, PCPE_CONTEXT PCPeCtx, void *PCPeInfoDetail, const int g_n[]) {

	int ArraySize = 0;
	WORD word;

	bool is64 = PCPeCtx->Is64Bit;

	// 机器架构
	word = PCPeCtx->pFileHeader->Machine;
	PCMachine_INFO pMachineInfo = (PCMachine_INFO)*(long long*)PCPeInfoDetail;
	ArraySize = g_n[0];
	for (int i = 0; i < ArraySize; i++) {
		if ((DWORD)word == pMachineInfo[i].dwValue) {
			SetDlgItemTextW(hPEInfoDetail, IDC_EDIT_MACHINE_DETAIL, pMachineInfo[i].pszDesc);
			break;
		}
	}

	// Magic
	word = is64 ? PCPeCtx->pOptHeader64->Magic : PCPeCtx->pOptHeader32->Magic;
	PCMagic_INFO pMagic_Info = (PCMagic_INFO) * (long long*)((BYTE*)PCPeInfoDetail + 8);
	ArraySize = g_n[1];
	for (int i = 0;i < ArraySize;i++) {
		if ((DWORD)word == pMagic_Info[i].dwValue) {
			SetDlgItemTextW(hPEInfoDetail, IDC_EDIT_MAGIC_DETAIL, pMagic_Info[i].pszDesc);
			break;
		}
	}

	// Subsystem
	word = is64 ? PCPeCtx->pOptHeader64->Subsystem : PCPeCtx->pOptHeader32->Subsystem;
	PCSubsystem_INFO pSubsystem_Info = (PCSubsystem_INFO) * (long long*)((BYTE*)PCPeInfoDetail + 16);
	ArraySize = g_n[2];
	for (int i = 0;i < ArraySize;i++) {
		if ((DWORD)word == pSubsystem_Info[i].dwValue) {
			SetDlgItemTextW(hPEInfoDetail, IDC_EDIT_SUBSYSTEM_DETAIL, pSubsystem_Info[i].pszDesc);
			break;
		}
	}

	// 时间戳
	// 格式化时间戳（Unix时间转本地时间）
	WCHAR timestring[32];
	PIMAGE_FILE_HEADER pFileHeader = PCPeCtx->pFileHeader;
	if (pFileHeader->TimeDateStamp == 0 || pFileHeader->TimeDateStamp == 0xFFFFFFFF) {
		wcscpy_s(timestring, _countof(timestring), L"无效时间戳");
	}
	else {
		// 方法1：使用 gmtime_s (C11 安全函数，UTC)
		__time32_t t = (__time32_t)pFileHeader->TimeDateStamp;
		struct tm utc_tm;
		if (_gmtime32_s(&utc_tm, &t) == 0) {
			wcsftime(timestring, _countof(timestring), L"%Y-%m-%d %H:%M:%S", &utc_tm);
		}
		else {
			wcscpy_s(timestring, _countof(timestring), L"转换失败");
		}
	}
	SetDlgItemTextW(hPEInfoDetail, IDC_EDIT_TIMEDATASTAMP_DETAIL, timestring);
}

// 初始化 Section Dlg
void InitSectionDlg(HWND hSectiondlg) {
	
	LVCOLUMNW lvc;
	memset(&lvc, 0, sizeof(LVCOLUMNW));

	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_LEFT;


	HWND hListSection = GetDlgItem(hSectiondlg, IDC_LIST_SECTION);
	HWND hListSectionCharac = GetDlgItem(hSectiondlg, IDC_LIST_SECTION_CHARAC);

	// 整行选中
	SendMessageW(hListSection, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);

	lvc.pszText = (LPWSTR)L"名称";
	lvc.cx = 100;
	SendMessageW(hListSection, LVM_INSERTCOLUMNW, 0, (LPARAM) & lvc);

	lvc.pszText = (LPWSTR)L"文件偏移";
	lvc.cx = 100;
	SendMessageW(hListSection, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"文件大小";
	lvc.cx = 100;
	SendMessageW(hListSection, LVM_INSERTCOLUMNW, 2, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"内存偏移";
	lvc.cx = 100;
	SendMessageW(hListSection, LVM_INSERTCOLUMNW, 3, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"内存大小";
	lvc.cx = 100;
	SendMessageW(hListSection, LVM_INSERTCOLUMNW, 4, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"节段属性";
	lvc.cx = 100;
	SendMessageW(hListSection, LVM_INSERTCOLUMNW, 5, (LPARAM)&lvc);


	// Section Characteristics List
	lvc.pszText = (LPWSTR)L"已置位";
	lvc.cx = 70;
	SendMessageW(hListSectionCharac, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"比特位含义";
	lvc.cx = 700;
	SendMessageW(hListSectionCharac, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);
}

// 填充 Section Charac List
void FillSectionCharacList(HWND hSectionDlg, PCSectionCharac g_SectionCharac, const int g_nSectionCharac) {

	LVITEMW lvi;
	memset(&lvi, 0, sizeof(LVITEMW));

	HWND hListSectionCharac = GetDlgItem(hSectionDlg, IDC_LIST_SECTION_CHARAC);
	HWND hListSection = GetDlgItem(hSectionDlg, IDC_LIST_SECTION);
	WCHAR szCharac[11] = { '\0' };

	// 获取选中项索引
	int iSelected = SendMessageW(hListSection, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (iSelected == -1) {
		SendMessageW(hListSectionCharac, LVM_DELETEALLITEMS, 0, 0);
		return;
	}


	lvi.iSubItem = 5;
	lvi.pszText = szCharac; // 获取选中项第5列字符串
	lvi.cchTextMax = 11;
	SendMessageW(hListSection, LVM_GETITEMTEXTW, iSelected, (LPARAM)&lvi);

	// 清空
	SendMessageW(hListSectionCharac, LVM_DELETEALLITEMS, 0, 0);

	// 转数字
	DWORD dwCharac = (DWORD)wcstoul(szCharac, NULL, 16);

	lvi.mask = LVIF_TEXT;
	int iRowIndex = 0;
	DWORD IsSet = 0;
	WCHAR bit[4];

	for (int i = 0;i < g_nSectionCharac;i++) {
		if (i <= 20) {
			IsSet = dwCharac & g_SectionCharac[i].dwValue;
			// 处理bit[1:20]
			if (IsSet) {
				swprintf_s(bit, L"%u", i);
				lvi.iItem = iRowIndex;
				lvi.iSubItem = 0;
				lvi.pszText = bit;
				SendMessageW(hListSectionCharac, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

				lvi.iItem = iRowIndex;
				lvi.iSubItem = 1;
				lvi.pszText = (LPWSTR)g_SectionCharac[i].pszDesc;
				SendMessageW(hListSectionCharac, LVM_SETITEMTEXTW, iRowIndex, (LPARAM)&lvi);
				iRowIndex++;
			}
		}
		else if (i <= 34) {
			//处理bit[21:24]
			IsSet = dwCharac & 0x00F00000;
			if (g_SectionCharac[i].dwValue == IsSet) {
				lvi.iItem = iRowIndex;
				lvi.iSubItem = 0;
				lvi.pszText = (LPWSTR)L"对齐";
				SendMessageW(hListSectionCharac, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

				lvi.iItem = iRowIndex;
				lvi.iSubItem = 1;
				lvi.pszText = (LPWSTR)g_SectionCharac[i].pszDesc;
				SendMessageW(hListSectionCharac, LVM_SETITEMTEXTW, iRowIndex, (LPARAM)&lvi);
				iRowIndex++;
				i = 34; // 跳过bit[21:24]
			}
		}
		else {
			//处理bit[25:32]
			IsSet = dwCharac & g_SectionCharac[i].dwValue;
			if (IsSet) {
				swprintf_s(bit, L"%u", i - 10); //修正比特
				lvi.iItem = iRowIndex;
				lvi.iSubItem = 0;
				lvi.pszText = bit;
				SendMessageW(hListSectionCharac, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

				lvi.iItem = iRowIndex;
				lvi.iSubItem = 1;
				lvi.pszText = (LPWSTR)g_SectionCharac[i].pszDesc;
				SendMessageW(hListSectionCharac, LVM_SETITEMTEXTW, iRowIndex, (LPARAM)&lvi);
				iRowIndex++;
			}
		}
	}
	// 自动宽度
	SendMessageW(hListSectionCharac, LVM_SETCOLUMNWIDTH, 1, LVSCW_AUTOSIZE);
}


// 填充 Directory Dlg
void FillDirectoryDlg(HWND hDirecDlg, PCPE_CONTEXT PCPeCtx) {

	bool is64 = PCPeCtx->Is64Bit;

	PIMAGE_DATA_DIRECTORY pDirectoryArray = is64 ? PCPeCtx->pOptHeader64->DataDirectory : PCPeCtx->pOptHeader32->DataDirectory;
	WCHAR Buffer[11] = { '\0' };
	const WCHAR Format[] = L"0x%X";
	const WCHAR SizeFormat[] = L"%X";

	// 导出表
	swprintf_s(Buffer, 11, Format, pDirectoryArray[0].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_EXPORTRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[0].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_EXPORTSIZE, Buffer);

	// 导入表
	swprintf_s(Buffer, 11, Format, pDirectoryArray[1].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_IMPORTRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[1].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_IMPORTSIZE, Buffer);

	// 资源表
	swprintf_s(Buffer, 11, Format, pDirectoryArray[2].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_RESOURCERVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[2].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_RESOURCESIZE, Buffer);

	// 异常表
	swprintf_s(Buffer, 11, Format, pDirectoryArray[3].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_EXCEPTIONRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[3].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_EXCEPTIONSIZE, Buffer);

	// 安全
	swprintf_s(Buffer, 11, Format, pDirectoryArray[4].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_SECURITYRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[4].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_SECURITYSIZE, Buffer);

	// 重定位
	swprintf_s(Buffer, 11, Format, pDirectoryArray[5].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_RELOCRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[5].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_RELOCSIZE, Buffer);

	// 调试
	swprintf_s(Buffer, 11, Format, pDirectoryArray[6].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_DEBUGRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[6].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_DEBUGSIZE, Buffer);

	// 版权
	swprintf_s(Buffer, 11, Format, pDirectoryArray[7].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_ARCHITECTURERVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[7].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_ARCHITECTURESIZE, Buffer);

	// 全局指针表
	swprintf_s(Buffer, 11, Format, pDirectoryArray[8].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_GLOBALPTRRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[8].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_GLOBALPTRSIZE, Buffer);

	// TLS
	swprintf_s(Buffer, 11, Format, pDirectoryArray[9].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_TLSRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[9].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_TLSSIZE, Buffer);

	// 导入配置
	swprintf_s(Buffer, 11, Format, pDirectoryArray[10].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_LOADCONFIGRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[10].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_LOADCONFIGSIZE, Buffer);

	// 绑定导入
	swprintf_s(Buffer, 11, Format, pDirectoryArray[11].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_BOUNDIMPORTRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[1].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_BOUNDIMPORTSIZE, Buffer);

	// IAT表
	swprintf_s(Buffer, 11, Format, pDirectoryArray[12].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_IATRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[12].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_IATSIZE, Buffer);

	// 延迟导入
	swprintf_s(Buffer, 11, Format, pDirectoryArray[13].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_DELAYIMPORTRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[13].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_DELAYIMPORTSIZE, Buffer);

	// COM
	swprintf_s(Buffer, 11, Format, pDirectoryArray[14].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_COMRVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[14].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_COMSIZE, Buffer);

	// 保留
	swprintf_s(Buffer, 11, Format, pDirectoryArray[15].VirtualAddress);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_RESERVERVA, Buffer);
	swprintf_s(Buffer, 11, SizeFormat, pDirectoryArray[15].Size);
	SetDlgItemTextW(hDirecDlg, IDC_EDIT_RESERVESIZE, Buffer);

}

void InitExportDetailDlg(HWND hExportDetail) {

	HWND hListExportDetail = GetDlgItem(hExportDetail, IDC_LIST_EXPORT);

	LVCOLUMNW lvc;
	memset(&lvc, 0, sizeof(LVCOLUMNW));
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_LEFT;

	// 导出序号
	lvc.pszText = (LPWSTR)L"导出序号";
	lvc.cx = 85;
	SendMessageW(hListExportDetail, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

	// 函数地址RVA
	lvc.pszText = (LPWSTR)L"函数地址RVA";
	lvc.cx = 100;
	SendMessageW(hListExportDetail, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);

	// 函数名称
	lvc.pszText = (LPWSTR)L"函数名称";
	lvc.cx = 200;
	SendMessageW(hListExportDetail, LVM_INSERTCOLUMNW, 2, (LPARAM)&lvc);

	// 函数FOA
	lvc.pszText = (LPWSTR)L"函数地址FOA";
	lvc.cx = 100;
	SendMessageW(hListExportDetail, LVM_INSERTCOLUMNW, 3, (LPARAM)&lvc);

	// 函数名称FOA
	lvc.pszText = (LPWSTR)L"理想VA";
	lvc.cx = 100;
	SendMessageW(hListExportDetail, LVM_INSERTCOLUMNW, 4, (LPARAM)&lvc);

}

// 详细解析数据目录项(0~15)并填充对话框
void ParseDirectoryDetail(HWND ToFillDlg, int DataDirecIndex, PCPE_CONTEXT PCPeCtx) {
	
	switch (DataDirecIndex)
	{
	case 0:
	{
		// 导出表
		ULONG64 PExportFoa = RvaToFoa(PCPeCtx, PCPeCtx->pDataDirectory[0].VirtualAddress);
		PIMAGE_EXPORT_DIRECTORY PExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)PCPeCtx->pBase + PExportFoa);
		HWND hListExport = GetDlgItem(ToFillDlg, IDC_LIST_EXPORT);
		DWORD Base = PExport->Base; // 导出序号基
		ULONG64 AddressOfFunctions = RvaToFoa(PCPeCtx, PExport->AddressOfFunctions) + (ULONG64)PCPeCtx->pBase;
		ULONG64 AddressOfNames = RvaToFoa(PCPeCtx, PExport->AddressOfNames) + (ULONG64)PCPeCtx->pBase;
		ULONG64 AddressOfNameOrdinals = RvaToFoa(PCPeCtx, PExport->AddressOfNameOrdinals) + (ULONG64)PCPeCtx->pBase;

		WCHAR Buffer[11] = { '\0' }; // 0x00000000
		WCHAR LongLongBuffer[19] = { '\0' }; // 0x00000000 00000000
		const WCHAR SizeFormat[] = L"%u";
		const WCHAR Format[] = L"0x%llX";

		LVITEMW lvi;
		memset(&lvi, 0, sizeof(LVITEMW));
		lvi.mask = LVIF_TEXT;

		// 导出函数数目
		DWORD NumberOfFunctions = PExport->NumberOfFunctions;
		// 按名字导出
		DWORD NumberOfNames = PExport->NumberOfNames;
		// 按序号导出
		DWORD NumberOfOrdinal = NumberOfFunctions - NumberOfNames;

		swprintf_s(Buffer, 11, SizeFormat, NumberOfFunctions);
		SetDlgItemTextW(ToFillDlg, IDC_EDIT_EXPORT_TOTAL, Buffer);
		swprintf_s(Buffer, 11, SizeFormat, NumberOfNames);
		SetDlgItemTextW(ToFillDlg, IDC_EDIT_EXPORT_BYNAME, Buffer);
		swprintf_s(Buffer, 11, SizeFormat, NumberOfOrdinal);
		SetDlgItemTextW(ToFillDlg, IDC_EDIT_EXPORT_BYORDINAL, Buffer);

		// 解析函数地址
		for (DWORD i = 0;i < NumberOfFunctions;i++) {
			// 导出序号
			swprintf_s(Buffer, 11, L"%X", i + Base);
			lvi.iItem = i;
			lvi.iSubItem = 0;
			lvi.pszText = Buffer;
			SendMessageW(hListExport, LVM_INSERTITEMW, 0, (LPARAM) & lvi);
			// 函数RVA
			ULONG32 FuncAddr = *((PLONG32)AddressOfFunctions + i);
			swprintf_s(LongLongBuffer, 19, Format, FuncAddr);
			lvi.pszText = LongLongBuffer;
			lvi.iItem = i;
			lvi.iSubItem = 1;
			SendMessageW(hListExport, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);
			// 函数理想VA
			ULONG64 FuncVA = (ULONG64)FuncAddr + PCPeCtx->ImageBase;
			swprintf_s(LongLongBuffer, 19, Format, FuncVA);
			lvi.pszText = LongLongBuffer;
			lvi.iItem = i;
			lvi.iSubItem = 4;
			SendMessageW(hListExport, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);
			// 函数名称
			lvi.pszText = (LPWSTR)L"-";
			lvi.iItem = i;
			lvi.iSubItem = 2;
			SendMessageW(hListExport, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);
			// 函数FOA
			FuncAddr = RvaToFoa(PCPeCtx, FuncAddr);
			swprintf_s(LongLongBuffer, 19, Format, FuncAddr);
			lvi.pszText = LongLongBuffer;
			lvi.iItem = i;
			lvi.iSubItem = 3;
			SendMessageW(hListExport, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);
		}
		// 解析函数名称
		std::vector<WCHAR> buffer(1024);
		for (DWORD i = 0;i < NumberOfNames;i++) {
			DWORD FuncNameRva = *((PLONG32)AddressOfNames + i);
			ULONG64 FuncNameFa = RvaToFoa(PCPeCtx, FuncNameRva) + (ULONG64)PCPeCtx->pBase;
			int FuncNameLen = MultiByteToWideChar(CP_ACP, 0, (LPCCH)FuncNameFa, -1, NULL, 0);

			if (FuncNameLen > buffer.size()) {
				buffer.resize(FuncNameLen);
			}

			MultiByteToWideChar(CP_ACP, 0, (LPCCH)FuncNameFa, -1, buffer.data(), FuncNameLen);
			WORD NameOrdinal = *((PWORD)AddressOfNameOrdinals + i);
			
			lvi.iItem = NameOrdinal;
			lvi.iSubItem = 2;
			lvi.pszText = buffer.data();
			SendMessageW(hListExport, LVM_SETITEMTEXTW, NameOrdinal, (LPARAM)&lvi);
		}
		SendMessageW(hListExport, LVM_SETCOLUMNWIDTH, 2, LVSCW_AUTOSIZE);
	}// 导出表
	break;
	case 1:
	{
		// 拿到导入表
		ULONG64 PImportFoa = RvaToFoa(PCPeCtx, PCPeCtx->pDataDirectory[1].VirtualAddress);
		PIMAGE_IMPORT_DESCRIPTOR PImport = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)PCPeCtx->pBase + PImportFoa);
		HWND hListImport = GetDlgItem(ToFillDlg, IDC_LIST_IMPORT);

		LVITEMW lvi = { 0 };
		lvi.mask = LVIF_TEXT;

		WCHAR dwBuffer[11] = { '\0' }; // 0x00000000
		WCHAR qwBuffer[19] = { '\0' }; // 0x00000000 00000000
		const WCHAR Format[] = L"0x%llX";
		std::vector<WCHAR> buffer(1024); // 存放名称

		// 循环读取（全0哨兵由Name代表）
		int i = 0;
		while (PImport->Name != 0) {
			swprintf_s(dwBuffer, 11, Format, PImport->OriginalFirstThunk);
			lvi.iItem = i;
			lvi.iSubItem = 0;
			lvi.pszText = dwBuffer;
			SendMessageW(hListImport, LVM_INSERTITEMW, 0, (LPARAM)& lvi);
			
			swprintf_s(dwBuffer, 11, Format, PImport->TimeDateStamp);
			lvi.iItem = i;
			lvi.iSubItem = 1;
			lvi.pszText = dwBuffer;
			SendMessageW(hListImport, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);

			swprintf_s(dwBuffer, 11, Format, PImport->FirstThunk);
			lvi.iItem = i;
			lvi.iSubItem = 2;
			lvi.pszText = dwBuffer;
			SendMessageW(hListImport, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);

			void* pName = (void*)(RvaToFoa(PCPeCtx, PImport->Name) + (BYTE*)PCPeCtx->pBase);
			int NameLen = MultiByteToWideChar(CP_ACP, 0, (LPCCH)pName, -1, NULL, 0);
			if (NameLen > buffer.size()) buffer.resize(NameLen);
			MultiByteToWideChar(CP_ACP, 0, (LPCCH)pName, -1, buffer.data(), NameLen);
			lvi.iItem = i;
			lvi.iSubItem = 3;
			lvi.pszText = buffer.data();
			SendMessageW(hListImport, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);
			
			i++;
			PImport++;
		}
		SendMessageW(hListImport, LVM_SETCOLUMNWIDTH, 3, LVSCW_AUTOSIZE);
	}// End导入表
	break;
	default: MessageBoxW(ToFillDlg, L"未支持索引或者错误索引", L"ParseDirectory", MB_OK);
	}
	return;
}

ULONG64 RvaToFoa(PCPE_CONTEXT PCPeCtx, ULONG64 Rva) {

	/**
	* 函数只能在 PCPeCtx 有效时使用，如果 PE 映射被释放则出现错误。
	*/

	bool is64 = PCPeCtx->Is64Bit;
	WORD NumberOfSections = PCPeCtx->pFileHeader->NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = PCPeCtx->pSectionHeader;

	DWORD SizeOfHeaders = is64 ? PCPeCtx->pOptHeader64->SizeOfHeaders : PCPeCtx->pOptHeader32->SizeOfHeaders;

	// RVA 在头部
	if (Rva <= (ULONG64)SizeOfHeaders) {
		return Rva;
	}

	// 在某个节里
	for (WORD i = 0; i < NumberOfSections;i++) {
		// 用文件大小可能更合适，因为实际上RVA肯定指向有效数据而不是尾部0填充
		if (Rva >= (ULONG64)pSectionHeader[i].VirtualAddress && (DWORD)Rva <= ((ULONG64)pSectionHeader[i].VirtualAddress + (ULONG64)pSectionHeader[i].SizeOfRawData)) {
			return (ULONG64)pSectionHeader[i].PointerToRawData + (Rva - (ULONG64)pSectionHeader[i].VirtualAddress);
		}
	}
	return 0;
}

void InitImportDetailDlg(HWND hImportDlg) {
	LVCOLUMNW lvc;
	memset(&lvc, 0, sizeof(LVCOLUMNW));
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_LEFT;

	HWND hListImport = GetDlgItem(hImportDlg, IDC_LIST_IMPORT);
	HWND hListImportFunc = GetDlgItem(hImportDlg, IDC_LIST_IMPORTFUNC);

	// OriginalFirstThunk TimeDateStamp FirstThunk Name
	lvc.pszText = (LPWSTR)L"OriginalFirstThunk";
	lvc.cx = 200;
	SendMessageW(hListImport, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"TimeDataStamp";
	lvc.cx = 150;
	SendMessageW(hListImport, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"FirstThunk";
	lvc.cx = 150;
	SendMessageW(hListImport, LVM_INSERTCOLUMNW, 2, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"Name";
	lvc.cx = 150;
	SendMessageW(hListImport, LVM_INSERTCOLUMNW, 3, (LPARAM)&lvc);

	// Original + Hint + Name
	lvc.pszText = (LPWSTR)L"Original";
	lvc.cx = 150;
	SendMessageW(hListImportFunc, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"Hint";
	lvc.cx = 150;
	SendMessageW(hListImportFunc, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"Name";
	lvc.cx = 150;
	SendMessageW(hListImportFunc, LVM_INSERTCOLUMNW, 2, (LPARAM)&lvc);
}