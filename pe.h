#pragma once
#include <windows.h>

/*步骤	API / 接口	作用
1	CoInitializeEx	初始化 COM 库（必须在最开始）。
2	CoCreateInstance	创建 IFileOpenDialog 对象。
3	IFileOpenDialog::SetFileTypes	设置文件过滤器（关键，用来只显示 PE 文件）。
4	IFileOpenDialog::Show	弹出对话框，等待用户选择。
5	IFileOpenDialog::GetResult	获取用户选择的结果（一个 IShellItem 对象）。
6	IShellItem::GetDisplayName	从结果中提取文件路径字符串。
7->Release() / CoUninitialize	释放 COM 对象，关闭 COM 库。*/

// 解析PE文件
// PE头 信息存储结构体
typedef struct _PE_CONTEXT {
    // 基础信息
    BOOL    Is64Bit;
    ULONG64   ImageBase;

    // 关键：保留映射信息
    HANDLE  hFile; // 文件句柄
    HANDLE  hMap;  // 映射对象
    LPVOID  pBase; // 映射的内存基址

    // 只存最核心的头指针（指向 pBase 内部，不拷贝）
    PIMAGE_DOS_HEADER         pDosHeader;   // Dos 头
    PIMAGE_NT_HEADERS32       pNtHeaders32; // 共用这个指向32/64位 NT Header
    PIMAGE_FILE_HEADER        pFileHeader;  // 文件头
    PIMAGE_OPTIONAL_HEADER32  pOptHeader32; // 如果是32位
    PIMAGE_OPTIONAL_HEADER64  pOptHeader64; // 如果是64位

    // 节表
    PIMAGE_SECTION_HEADER     pSectionHeader;
    // 数据目录
    PIMAGE_DATA_DIRECTORY     pDataDirectory;


} PE_CONTEXT, * PPE_CONTEXT;
typedef const PE_CONTEXT* PCPE_CONTEXT;


typedef struct _CHARACTERISTIC_INFO {
    DWORD dwValue;      // 标志位的值
    LPCWSTR pszDesc;    // 详细描述
} CHARACTERISTIC_INFO;
typedef const CHARACTERISTIC_INFO* PCCHARACTERISTIC_INFO;
// 配置表：Characteristics 标志位
extern const CHARACTERISTIC_INFO g_CharacteristicsFlags[];
// 配置表：DllCharacteristics 标志位
extern const CHARACTERISTIC_INFO g_DllCharacteristicsFlags[];

// 同时需要声明数组长度，供外部循环使用
extern const int g_nCharacteristicsFlagsCount;
extern const int g_nDllCharacteristicsFlagsCount;

// 机器架构 配置表
typedef struct _Machine_INFO {
    DWORD dwValue;
    LPCWSTR pszDesc;
}Machine_INFO, * Pachine_INFO;
typedef const Machine_INFO* PCMachine_INFO;

extern const Machine_INFO g_Machine_INFO[];
extern const int g_nMachine_INFO;

// Magic 
typedef struct _Magic_INFO {
    DWORD dwValue;
    LPCWSTR pszDesc;
}Magic_INFO, * PMagic_INFO;
typedef const Magic_INFO* PCMagic_INFO;
extern const Magic_INFO g_Magic_INFO[];
extern const int g_nMagic_INFO;

// Subsystem
typedef struct _Subsystem_INFO {
    DWORD dwValue;
    LPCWSTR pszDesc;
}Subsystem_INFO, * PSubsystem_INFO;
typedef const Subsystem_INFO* PCSubsystem_INFO;
extern const Subsystem_INFO g_Subsystem_INFO[];
extern const int g_nSubsystem_INFO;

// 节属性字典
typedef struct _SectionCharac {
    DWORD dwValue;
    LPCWSTR pszDesc;
} SectionCharac, * PSectionCharac;
typedef const SectionCharac* PCSectionCharac;

extern const SectionCharac g_SectionCharac[];
extern const int g_nSectionCharac;

// 释放 PE 映射
void ClosePeFile(PPE_CONTEXT pPeCtx);

// 弹出文件选择界面并获取路径
bool OpenPEFile(HWND hPEInfo, LPWSTR FilePathName, size_t destSize);

// PE 解析函数 [out] pPeInfo
HRESULT ParsePeContext(LPCWSTR pszFilePath, PPE_CONTEXT pPeCtx);

// 填写 PE Info UI
void FillPeHeaderToUi(HWND hPEInfo, PCPE_CONTEXT PeCtx);

// 填充 PE Info Detail UI
void FillPEInfoDetailUI(HWND hPEInfoDetail, PCPE_CONTEXT PCPeCtx, void* PCPeInfoDetail, const int g_n[]);

// 填写 Characteristics Detail UI
void FillCharacToUI(HWND hCharacDetail, const int CharacteristicsFlagsCount, WORD wAvtiveFlags, PCCHARACTERISTIC_INFO pcCharacInfoArray);

// 打开 PE Info 界面的所有处理逻辑(OpenPEFile + ParsePeHeader + DialogBoxW)
void OpenPEInfo(HINSTANCE hpexplore, HWND hdlg, WNDPROC PEInfoDialogProc);

// 初始化 Characteristic Detail 对话框
void InitCharacDialog(HWND hCharacDetail);

// 填充 Section Dialog
void FillSectionDialog(HWND hSectionDlg, PCPE_CONTEXT PCPeCtx);

// 初始化 Section Dlg
void InitSectionDlg(HWND hSectiondlg);

// 填充 Section Charac List
void FillSectionCharacList(HWND hSectionDlg, PCSectionCharac g_SectionCharac, const int g_nSectionCharac);

// 填充 Directory Dlg
void FillDirectoryDlg(HWND hDirecDlg, PCPE_CONTEXT PCPeCtx);

// 初始化 Export Detail Dlg
void InitExportDetailDlg(HWND ExportDetail);

// 详细解析数据目录项(0~15)并填充对话框
void ParseDirectoryDetail(HWND ToFillDlg, int DataDirecIndex, PCPE_CONTEXT PCPeCtx);

// RVA 转 FOA
ULONG64 RvaToFoa(PCPE_CONTEXT PCPeCtx, ULONG64 Rva);

// 初始化 Import Detail Dlg
void InitImportDetailDlg(HWND hImportDlg);

// 详细解析数据目录项(0~15)并填充对话框
void ParseDirectoryDetail(HWND ToFillDlg, int DataDirecIndex, PCPE_CONTEXT PCPeCtx);