#include <windows.h>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")
#include "resource.h"
#include "Init.h"
#include "pe.h"
#include "subwndproc.h"

HINSTANCE hpexplore = NULL; // 全局用户模块句柄

INT_PTR CALLBACK MainDialogProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

int WINAPI wWinMain(
	HINSTANCE hInstance, //应用程序的当前模块句柄，一般是ImageBase
	HINSTANCE hPrevInstance,// 应用程序的上一个实例的句柄。 此参数始终NULL。已经不再使用
	LPWSTR    lpCmdLine,//应用程序的命令行，不包括程序名称。
	int       nShowCmd //控制窗口的显示方式。
) 
{
	hpexplore = hInstance;
	// 初始化通用控件，告诉PE加载器使用哪种通用控件
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);  // 必须填结构体大小
	icex.dwICC = ICC_WIN95_CLASSES;           // 关键：指定要初始化【什么】控件
	InitCommonControlsEx(&icex);
/*	
DialogBoxW(
	HINSTANCE hInstance, // 模块句柄
	LPCTSTR lpTemplate, // 资源标识符
	HWND hWndParent, // 父窗口
	DLGPROC lpDialogFunc // 对话框消息处理函数
)

INT_PTR Dlgproc(
	HWND hwnd,
	UINT msg,
	WPARAM wparam,
	LPARAM lparam
);
*/
	
	DialogBoxW(hpexplore, (LPCTSTR)IDD_DIALOG_MAIN, NULL, MainDialogProc);
}

INT_PTR CALLBACK MainDialogProc(HWND hdlg, UINT msg, WPARAM wparam, LPARAM lparam) {
	switch (msg)
	{
	case WM_INITDIALOG:
		InitProcessListView(hdlg);
		InitModuleListView(hdlg);
		EnumProcess(GetDlgItem(hdlg, IDC_LIST_PROCESS));
		return TRUE;
	case WM_CLOSE:
		EndDialog(hdlg, 0);
		return TRUE;
	case WM_COMMAND:
	{
		switch (LOWORD(wparam))
		{
		case IDC_BUTTON_PE:
		{
			OpenPEInfo(hpexplore, hdlg, PEInfoDialogProc);
			return TRUE;
		}
		case IDC_BUTTON_ABOUT:
			MessageBoxW(hdlg, L"喵喵喵~", L"ZORCOR", MB_OK);
			return TRUE;
		case IDC_BUTTON_EXIT:
			EndDialog(hdlg, 0);
			return TRUE;
		}
	}
	break;
	case WM_NOTIFY:
	{
		if (wparam == IDC_LIST_PROCESS && ((NMHDR*)lparam)->code == NM_CLICK) {
			EnumModule(GetDlgItem(hdlg, IDC_LIST_MODULE), GetDlgItem(hdlg, IDC_LIST_PROCESS));
			return TRUE;
		}
	}
	break;
	}
	return FALSE;
}
