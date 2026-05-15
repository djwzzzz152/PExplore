#include "subwndproc.h"
#include "resource.h"
#include "pe.h"
#include <commctrl.h>


PE_CONTEXT PeCtx;
INT_PTR CALLBACK PEInfoDialogProc(HWND hPEInfo, UINT msg, WPARAM wparam, LPARAM lparam) {

	switch (msg) 
	{
	case WM_INITDIALOG:
		memcpy(&PeCtx, (PCPE_CONTEXT)lparam, sizeof(PE_CONTEXT));
		FillPeHeaderToUi(hPEInfo, &PeCtx);
		return TRUE; 
	case WM_CLOSE:
		ClosePeFile(&PeCtx);
		memset(&PeCtx, 0, sizeof(PE_CONTEXT));
		EndDialog(hPEInfo, 0);
		return TRUE;

	case WM_COMMAND:
	{
		switch (LOWORD(wparam))
		{
		case IDC_BUTTON_CLOSE_PEINFO:
			ClosePeFile(&PeCtx);
			memset(&PeCtx, 0, sizeof(PE_CONTEXT));
			EndDialog(hPEInfo, 0);
			return TRUE;
		case IDC_BUTTON_PEINFO_DETAIL:
			DialogBoxParamW(GetModuleHandleW(NULL), (LPCWSTR)IDD_DIALOG_PEINFO_DETAIL, hPEInfo, PEInfoDetailDialogProc, (LPARAM)hPEInfo);
			return TRUE;
		case IDC_BUTTON_CHARACTERISTIC_DETAIL:
		{

			struct _temp{
				const int ArraySize;
				PCCHARACTERISTIC_INFO pFlagsInfoArray;
				int CharacOrDLLChara; // 0 for Charac, 1 for DllCharac
			};
			struct _temp temp = { g_nCharacteristicsFlagsCount,g_CharacteristicsFlags, 0};

			DialogBoxParamW(GetModuleHandleW(NULL), (LPCWSTR)IDD_DIALOG_CHARACTERISTIC_DETAIL, hPEInfo, CharacDetailDialogProc, (LPARAM)&temp);
			return TRUE;

		}
		case IDC_BUTTON_DLLCHARACTERISTIC_DETAIL:
		{

			struct _temp {
				const int ArraySize;
				PCCHARACTERISTIC_INFO pFlagsInfoArray;
				int CharacOrDLLChara;
			};
			struct _temp temp = { g_nDllCharacteristicsFlagsCount,g_DllCharacteristicsFlags, 1};

			DialogBoxParamW(GetModuleHandleW(NULL), (LPCWSTR)IDD_DIALOG_CHARACTERISTIC_DETAIL, hPEInfo, CharacDetailDialogProc, (LPARAM)&temp);
			return TRUE;

		}
		case IDC_BUTTON_DIRECTORY:
			DialogBoxW(GetModuleHandleW(NULL), (LPCWSTR)IDD_DIALOG_DIRECTORY, hPEInfo, DirecDlgProc);
			return TRUE;
		case IDC_BUTTON_SECTION:
			DialogBoxW(GetModuleHandleW(NULL), (LPCWSTR)IDD_DIALOG_SECTION, hPEInfo, SectionDialogProc);
			return TRUE;
		}
	}
	break;
	}

	return FALSE;
}


INT_PTR CALLBACK PEInfoDetailDialogProc(HWND hPEInfoDetail, UINT msg, WPARAM wparam, LPARAM lparam) {
	switch (msg)
	{
	case WM_INITDIALOG:
	{

		struct _temp {
			PCMachine_INFO pcmachineinfo;
			PCMagic_INFO pcmagicinfo;
			PCSubsystem_INFO pcsubsysteminfo;
		};
		struct _temp temp= { g_Machine_INFO ,g_Magic_INFO ,g_Subsystem_INFO };
		const int arr[] = { g_nMachine_INFO ,g_nMagic_INFO ,g_nSubsystem_INFO };
		FillPEInfoDetailUI(hPEInfoDetail, &PeCtx, &temp, arr);
		return TRUE;
	}
	case WM_CLOSE:
		EndDialog(hPEInfoDetail, 0);
		return TRUE;

	}
	return FALSE;
}

INT_PTR CALLBACK CharacDetailDialogProc(HWND hCharacDetail, UINT msg, WPARAM wparam, LPARAM lparam) {
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		InitCharacDialog(hCharacDetail);

		bool is64 = PeCtx.Is64Bit;

		if (*(int*)((BYTE*)lparam + 16) == 0) {
			FillCharacToUI(hCharacDetail, (const int)*(int*)lparam, PeCtx.pFileHeader->Characteristics, (PCCHARACTERISTIC_INFO) * (long long*)((BYTE*)lparam + 8));
		}
		else if (*(int*)((BYTE*)lparam + 16) == 1) {
			FillCharacToUI(hCharacDetail, (const int)*(int*)lparam, is64 ? PeCtx.pOptHeader64->DllCharacteristics : PeCtx.pOptHeader32->DllCharacteristics, (PCCHARACTERISTIC_INFO) * (long long*)((BYTE*)lparam + 8));
		}
		return TRUE;
	}
	case WM_CLOSE:
		EndDialog(hCharacDetail, 0);
		return TRUE;

	}
	return FALSE;
}


INT_PTR CALLBACK SectionDialogProc(HWND hCharacDetail, UINT msg, WPARAM wparam, LPARAM lparam) {
	switch (msg)
	{
	case WM_INITDIALOG:
		InitSectionDlg(hCharacDetail);
		FillSectionDialog(hCharacDetail, &PeCtx);
		return TRUE;
	case WM_NOTIFY:
	{
		if (wparam == IDC_LIST_SECTION && ((NMHDR*)lparam)->code == NM_CLICK) {
			FillSectionCharacList(hCharacDetail, g_SectionCharac, g_nSectionCharac);
			return TRUE;
		}
	}
	break;
	case WM_CLOSE:
		EndDialog(hCharacDetail, 0);
		return TRUE;
	}
	return FALSE;
}

INT_PTR CALLBACK DirecDlgProc(HWND hDirecDlg, UINT msg, WPARAM wparam, LPARAM lparam) {
	switch (msg)
	{
	case WM_INITDIALOG:
		FillDirectoryDlg(hDirecDlg, &PeCtx);
		return TRUE;
	case WM_CLOSE:
		EndDialog(hDirecDlg, 0);
		return TRUE;
	case WM_COMMAND:
	{
		switch (LOWORD(wparam))
		{
		case IDC_BUTTON_DIRECTORY_CLOSE:
			EndDialog(hDirecDlg, 0);
			return TRUE;
		case IDC_BUTTON_EXPORT_DETAIL:
			if (PeCtx.pDataDirectory[0].VirtualAddress == 0) {
				MessageBoxW(hDirecDlg, L"导出表不存在！", L"DirecDlgProc", MB_OK);
				break;
			}
			DialogBoxW(GetModuleHandleW(NULL), (LPCWSTR)IDD_DIALOG_EXPORT_DETAIL, hDirecDlg, ExportDetailProc);
			return TRUE;
		case IDC_BUTTON_IMPORT_DETAIL:
			if (PeCtx.pDataDirectory[1].VirtualAddress == 0) {
				MessageBoxW(hDirecDlg, L"导入表不存在！", L"DirecDlgProc", MB_OK);
				break;
			}
			DialogBoxW(GetModuleHandleW(NULL), (LPCWSTR)IDD_DIALOG_IMPORT_DETAIL, hDirecDlg, ImportDetailProc);
			return TRUE;
		}
	}
	break;
	}
	return FALSE;
}

INT_PTR CALLBACK ExportDetailProc(HWND hExportDetail, UINT msg, WPARAM wparam, LPARAM lparam) {
	switch (msg)
	{
	case WM_INITDIALOG:
		InitExportDetailDlg(hExportDetail);
		ParseDirectoryDetail(hExportDetail, 0, &PeCtx);
		return TRUE;
	case WM_CLOSE:
		EndDialog(hExportDetail, 0);
		return TRUE;
	}
	return FALSE;
}

INT_PTR CALLBACK ImportDetailProc(HWND hImportDetail, UINT msg, WPARAM wparam, LPARAM lparam) {
	switch (msg)
	{
	case WM_INITDIALOG:
		InitImportDetailDlg(hImportDetail);
		ParseDirectoryDetail(hImportDetail, 1, &PeCtx);
		return TRUE;
	case WM_CLOSE:
		EndDialog(hImportDetail, 0);
		return TRUE;
	}
	return FALSE;
}