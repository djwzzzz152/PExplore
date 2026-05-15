#include "Init.h"
#include <commctrl.h>
#include <tlhelp32.h>
#include "resource.h"

void InitProcessListView(HWND hdlg) {
	LV_COLUMNW lvc;
	HWND hListProcess = NULL;

	memset(&lvc, 0, sizeof(LV_COLUMNW));
	// 获取IDC_LIST_PROCESS句柄资源
	hListProcess = GetDlgItem(hdlg, IDC_LIST_PROCESS);
	//鼠标点击整行选中
	SendMessageW(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);

	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lvc.fmt = LVCFMT_LEFT; // 左对齐文本

	//第1列
	lvc.pszText = (LPWSTR)L"进程"; // 标题
	lvc.cx = 200; // 列像素宽度
	lvc.iSubItem = 0; // 理解为第几列
	//在列表视图控件中插入新列。 可以显式发送此消息
	SendMessageW(hListProcess, LVM_INSERTCOLUMNW, lvc.iSubItem, (LPARAM)&lvc);
	//第2列
	lvc.pszText = (LPWSTR)L"PID";
	lvc.cx = 60;
	lvc.iSubItem = 1;
	SendMessageW(hListProcess, LVM_INSERTCOLUMNW, lvc.iSubItem, (LPARAM)&lvc);
	//第3列
	lvc.pszText = (LPWSTR)L"镜像基址";
	lvc.cx = 200;
	lvc.iSubItem = 2;
	SendMessageW(hListProcess, LVM_INSERTCOLUMNW, lvc.iSubItem, (LPARAM)&lvc);
	//第4列
	lvc.pszText = (LPWSTR)L"镜像大小";
	lvc.cx = 100;
	lvc.iSubItem = 3;
	SendMessageW(hListProcess, LVM_INSERTCOLUMNW, lvc.iSubItem, (LPARAM)&lvc);
}

void InitModuleListView(HWND hdlg) {
	LV_COLUMNW lvc;
	HWND hListModule;

	// 获取模块列表窗口句柄
	memset(&lvc, 0, sizeof(LV_COLUMNW));
	hListModule = GetDlgItem(hdlg, IDC_LIST_MODULE);
	//鼠标点击整行选中
	SendMessageW(hListModule, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);

	// 插入列
	lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

	lvc.pszText = (LPWSTR)L"模块名称";
	lvc.cx = 450;
	lvc.iSubItem = 0;
	SendMessageW(hListModule, LVM_INSERTCOLUMNW, lvc.iSubItem, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"模块基址";
	lvc.cx = 200;
	lvc.iSubItem = 1;
	SendMessageW(hListModule, LVM_INSERTCOLUMNW, lvc.iSubItem, (LPARAM)&lvc);

	lvc.pszText = (LPWSTR)L"模块大小";
	lvc.cx = 100;
	lvc.iSubItem = 2;
	SendMessageW(hListModule, LVM_INSERTCOLUMNW, lvc.iSubItem, (LPARAM)&lvc);
}

void EnumProcess(HWND hListProcess) {
	// 第一步：拍一张进程快照
	// TH32CS_SNAPPROCESS 表示我们要枚举所有进程
	// 0表示所有进程，具体PID表示具体进程
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		MessageBoxW(hListProcess, L"枚举进程失败，无效句柄值。", L"CreateToolhelp32Snapshot", MB_OK);
		return;
	}

	// 进程信息结构体，用于存储一个进程信息
	PROCESSENTRY32W pe32;
	memset(&pe32, 0, sizeof(PROCESSENTRY32W));
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	// 进程模块信息结构体
	MODULEENTRY32W me32;
	memset(&me32, 0, sizeof(MODULEENTRY32W));
	me32.dwSize = sizeof(MODULEENTRY32W);
	// 存储项信息的结构体
	LVITEMW lvi;
	memset(&lvi, 0, sizeof(LVITEMW));
	lvi.mask = LVIF_TEXT; // 设置文本
	// 暂时存储4个字段的信息
	WCHAR* pName; // 进程名字
	WCHAR szPID[16]; // 存储PID
	WCHAR szBaseAddr[32]; // 用来存 ImageBase 字符串
	WCHAR szSize[32]; // 用来存 ImageSize 字符串


	// 复制进程信息,插入到进程列表中
	// Process32FirstW参数：快照句柄，进程信息结构体指针

	// 第二步：获得名字+PID+ImageBase+ImageSize
	int iRowIndex = 0;
	if (Process32FirstW(hSnapshot, &pe32)) {
		do {

			pName = pe32.szExeFile; //名称
			wsprintfW(szPID, L"%u", pe32.th32ProcessID); // PID
			// 可能遍历模块失败，每次初始化为0防止字符串问题
			szBaseAddr[0] = L'\0';
			szSize[0] = L'\0';
			// 拍当前进程模块快照获取基址和大小 TH32CS_SNAPMODULE 需要传入具体的 PID
			HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
			if (hModuleSnap != INVALID_HANDLE_VALUE) {
				// 一般EXE都是第一个模块，只拿第一个就行了
				if (Module32FirstW(hModuleSnap, &me32)) {
					wsprintfW(szBaseAddr, L"0x%p", me32.modBaseAddr); // ImageBase
					wsprintfW(szSize, L"%X", me32.modBaseSize); // ImageSize
				}
				CloseHandle(hModuleSnap);
			}
			
			// 第三步：插入4个字段内容
			lvi.iItem = iRowIndex;
			lvi.iSubItem = 0;
			lvi.pszText = pName;
			SendMessageW(hListProcess, LVM_INSERTITEMW, iRowIndex, (LPARAM)&lvi);

			lvi.pszText = szPID;
			lvi.iSubItem = 1;
			SendMessageW(hListProcess, LVM_SETITEMTEXTW, iRowIndex, (LPARAM)&lvi);

			lvi.pszText = szBaseAddr;
			lvi.iSubItem = 2;
			SendMessageW(hListProcess, LVM_SETITEMTEXTW, iRowIndex, (LPARAM)&lvi);

			lvi.pszText = szSize;
			lvi.iSubItem = 3;
			SendMessageW(hListProcess, LVM_SETITEMTEXTW, iRowIndex, (LPARAM)&lvi);

			iRowIndex++; //下一行
		} while (Process32NextW(hSnapshot, &pe32));
		CloseHandle(hSnapshot);
		return;
	} else {
		MessageBoxW(hListProcess, L"进程信息复制错误", L"Process32FirstW", MB_OK);
		CloseHandle(hSnapshot); // 记得关闭句柄
		return;
	}
}


void EnumModule(HWND hListModule, HWND hListProcess) {
	/*
		1. 获取选中项的PID
		2. 清空上次结果
		3. 根据 PID 拍一张进程快照
		4. 从快照中循环获取模块内容，插入到 Module List
	*/

	// 选中项索引
	int iSelected = 0;
	// 存储PID
	WCHAR szPID[16] = {'\0'};
	// 存储项信息的结构体
	LVITEMW lvi;
	memset(&lvi, 0, sizeof(LVITEM));

	// 1. 获取选中项PID
	iSelected = SendMessageW(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (iSelected == -1) {
		SendMessageW(hListModule, LVM_DELETEALLITEMS, 0, 0);
		return;
	}
	
	lvi.iSubItem = 1;
	lvi.pszText = szPID;
	lvi.cchTextMax = 16;
	SendMessageW(hListProcess, LVM_GETITEMTEXTW, iSelected, (LPARAM)&lvi);

	// 2. 清空残留项
	SendMessageW(hListModule, LVM_DELETEALLITEMS, 0, 0);

	//3. 根据 PID 拍一张进程快照
		// 将ID转换成数字
	DWORD dwPid = _wtoi(szPID);
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		MessageBoxW(hListProcess, L" 可能是权限不够，或者是系统进程，无法遍历模块", L"CreateToolhelp32Snapshot", MB_OK);
		return;
	}

	// 存储模块信息的结构体
	MODULEENTRY32W me32;
	memset(&me32, 0, sizeof(MODULEENTRY32W));
	me32.dwSize = sizeof(MODULEENTRY32W);
	// 存储项信息的结构体
	lvi.mask = LVIF_TEXT;
	// 暂存模块基址和大小
	WCHAR szBaseAddr[32];
	WCHAR szSize[32];

	//4. 从快照中循环获取模块内容，插入到 Module List
	int iRowIndex = 0;
	if (Module32FirstW(hModuleSnap, &me32)) {

		do {

			wsprintfW(szBaseAddr, L"0x%p", me32.modBaseAddr); // 格式化基址字符串
			wsprintfW(szSize, L"%X", me32.modBaseSize); // 格式化大小字符串

			lvi.iItem = iRowIndex;
			lvi.iSubItem = 0;
			lvi.pszText = me32.szModule; // 模块名字
			SendMessageW(hListModule, LVM_INSERTITEMW, iRowIndex, (LPARAM)&lvi);

			lvi.iSubItem = 1;
			lvi.pszText = szBaseAddr; // 基址
			SendMessageW(hListModule, LVM_SETITEMTEXTW, iRowIndex, (LPARAM)&lvi);

			lvi.iSubItem = 2;
			lvi.pszText = szSize; // 大小
			SendMessageW(hListModule, LVM_SETITEMTEXTW, iRowIndex, (LPARAM)&lvi);

			iRowIndex++;
		} while (Module32NextW(hModuleSnap, &me32));

		CloseHandle(hModuleSnap);
		return;
	} else {
		MessageBoxW(hListProcess, L"模块信息复制错误", L"Module32FirstW", MB_OK);
		CloseHandle(hModuleSnap); // 记得关闭句柄
		return;
	}
}