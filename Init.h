#pragma once
#include <windows.h>
void InitProcessListView(HWND hwnd); //初始化进程视图列表
void InitModuleListView(HWND hwnd); //初始化模块视图
//-------测试--------

//-------测试--------
void EnumProcess(HWND hListProcess); //枚举所有进程
void EnumModule(HWND hListModule,HWND hListProcess); //枚举当前进程所有模块
