#pragma once
#include <windows.h>

// PE Info 消息处理
INT_PTR CALLBACK PEInfoDialogProc(HWND hPEInfo, UINT msg, WPARAM wparam, LPARAM lparam);

// PE Info Detail 消息处理
INT_PTR CALLBACK PEInfoDetailDialogProc(HWND hPEInfoDetail, UINT msg, WPARAM wparam, LPARAM lparam);

// Characteristick Detail 消息处理
INT_PTR CALLBACK CharacDetailDialogProc(HWND hPEInfoDetail, UINT msg, WPARAM wparam, LPARAM lparam);

// Section dlg 消息处理
INT_PTR CALLBACK SectionDialogProc(HWND hCharacDetail, UINT msg, WPARAM wparam, LPARAM lparam);

// Directory Dlg 消息处理
INT_PTR CALLBACK DirecDlgProc(HWND hDirecDlg, UINT msg, WPARAM wparam, LPARAM lparam);

// Export Detail Dlg 消息处理
INT_PTR CALLBACK ExportDetailProc(HWND hExportDetail, UINT msg, WPARAM wparam, LPARAM lparam);

// Import Detail Dlg 消息处理
INT_PTR CALLBACK ImportDetailProc(HWND hExportDetail, UINT msg, WPARAM wparam, LPARAM lparam);