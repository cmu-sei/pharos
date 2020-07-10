// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

// cl /EHsc  /MD ApiGraphTestProgram.cc
#include <windows.h>
#include <Winreg.h>
#include <iostream>

#pragma comment(lib,"advapi32")

HMODULE Func();
HMODULE Func2();


DWORD WINAPI ArgSameProc() {
   //Variable Decle
   HANDLE stdinRd, stdinWr, stdoutRd, stdoutWr;
   SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, true};
   STARTUPINFO si;
   PROCESS_INFORMATION pi;
   DWORD stuff;
   char buff[1000], recvBuff[5];
   bool firstsend;
   int offset = 0, bRecv;

   //Create the main transfer pipe
   if(!CreatePipe(&stdinRd, &stdinWr, &sa, 0) || !CreatePipe(&stdoutRd, &stdoutWr, &sa, 0)) {
     return 1;
   }

   //Get Process Startup Info
   GetStartupInfo(&si);
   si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
   si.wShowWindow = SW_HIDE;
   si.hStdOutput = stdoutWr;
   si.hStdError = stdoutWr;
   si.hStdInput = stdinRd;

   //Create the CMD Shell using the process startup info above
   if(!CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
     return 1;
   }

   //Main while(1) Loop
   while(1)
   {
       Sleep(100);
       //Check if cmd.exe has not stoped
       GetExitCodeProcess(pi.hProcess, &stuff);
       //Stop the while loop if not active
       if(stuff != STILL_ACTIVE) break;

       //Copy Data from buffer to pipe and vise versa
       PeekNamedPipe(stdoutRd, NULL, 0, NULL, &stuff, NULL);
       if(stuff != 0) {
           //Zero buffer meomry
           ZeroMemory(buff, sizeof(buff));
           firstsend = true;

           do {
             ReadFile(stdoutRd, buff, 1000, &stuff, NULL);
           } while(stuff == 1000);
       }
       WriteFile(stdinWr, recvBuff, strlen(recvBuff), &stuff, NULL);
       offset = offset + bRecv;
   }

   //Cleaning up functions
   TerminateProcess(pi.hProcess, 0);
   CloseHandle(stdinRd);
   CloseHandle(stdinWr);
   CloseHandle(stdoutRd);
   CloseHandle(stdoutWr);

   return 0;
}

int DoRead(HANDLE h,char buff[]) {

  DWORD stuff;
  do {
    ReadFile(h, buff, 1000, &stuff, NULL);
  } while(stuff == 1000);
  return 1;
}

int Check(HANDLE h1, char buff[]) {
  if (h1 == 0) return 0;
  return DoRead(h1, buff);
}

void Read(HANDLE h, char buff[]) {
  Check(h,buff);

}

int ArgInterprocedural() {
  //Variable Decle
  HANDLE stdinRd, stdinWr, stdoutRd, stdoutWr;
  SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, true};
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  DWORD stuff;
  char buff[1000], recvBuff[5];
  bool firstsend;
  int offset = 0, bRecv;

  //Create the main transfer pipe
  if(!CreatePipe(&stdinRd, &stdinWr, &sa, 0) || !CreatePipe(&stdoutRd, &stdoutWr, &sa, 0)) {
    return 1;
  }

  //Get Process Startup Info
  GetStartupInfo(&si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = stdoutWr;
  si.hStdError = stdoutWr;
  si.hStdInput = stdinRd;

  //Create the CMD Shell using the process startup info above
  if(!CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
    return 1;
  }

  //Main while(1) Loop
  while(1) {
      Sleep(100);
      //Check if cmd.exe has not stoped
      GetExitCodeProcess(pi.hProcess, &stuff);
      //Stop the while loop if not active
      if(stuff != STILL_ACTIVE) break;

      //Copy Data from buffer to pipe and vise versa
      PeekNamedPipe(stdoutRd, NULL, 0, NULL, &stuff, NULL);
      if(stuff != 0) {
        //Zero buffer meomry
        ZeroMemory(buff, sizeof(buff));
        firstsend = true;

        Check(stdoutRd, buff);
      }
      WriteFile(stdinWr, recvBuff, strlen(recvBuff), &stuff, NULL);
      offset = offset + bRecv;
    }

  //Cleaning up functions
  TerminateProcess(pi.hProcess, 0);
  CloseHandle(stdinRd);
  CloseHandle(stdinWr);
  CloseHandle(stdoutRd);
  CloseHandle(stdoutWr);

  return 0;
}

int OutParamMatchIntra() {

 //Variable Decle
  HANDLE stdinRd, stdinWr, stdoutRd, stdoutWr;
  SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, true};
  DWORD stuff;
  char buff[1000];
  bool firstsend;
  int offset = 0, bRecv;

  if(!CreatePipe(&stdinRd, &stdinWr, &sa, 0)) {
    return 1;
  }

  ReadFile(stdinRd, buff, 1000, &stuff, NULL);

  WriteFile(stdinWr,buff,1000, &stuff,NULL);

}

int ArgNoMatch() {

  //Variable Decle
  HANDLE stdinRd, stdinWr, stdoutRd, stdoutWr;
  SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, true};
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  DWORD stuff;
  char buff[1000], recvBuff[5];
  bool firstsend;
  int offset = 0, bRecv;

  //Create the main transfer pipe
  if(!CreatePipe(&stdinRd, &stdinWr, &sa, 0) || !CreatePipe(&stdoutRd, &stdoutWr, &sa, 0)) {
    return 1;
  }

  //Get Process Startup Info
  GetStartupInfo(&si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = stdoutWr;
  si.hStdError = stdoutWr;
  si.hStdInput = stdinRd;

  //Create the CMD Shell using the process startup info above
  if(!CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
    return 1;
  }

  //Main while(1) Loop
  while(1) {
      Sleep(100);
      //Check if cmd.exe has not stoped
      GetExitCodeProcess(pi.hProcess, &stuff);
      //Stop the while loop if not active
      if(stuff != STILL_ACTIVE) break;

      //Copy Data from buffer to pipe and vise versa
      PeekNamedPipe(stdoutRd, NULL, 0, NULL, &stuff, NULL);
      if(stuff != 0) {
        //Zero buffer meomry
        ZeroMemory(buff, sizeof(buff));
        firstsend = true;

        ReadFile(stdinRd, buff, 1000, &stuff, NULL);

      }
      WriteFile(stdinWr, recvBuff, strlen(recvBuff), &stuff, NULL);
      offset = offset + bRecv;
    }

  //Cleaning up functions
  TerminateProcess(pi.hProcess, 0);
  CloseHandle(stdinRd);
  CloseHandle(stdinWr);
  CloseHandle(stdoutRd);
  CloseHandle(stdoutWr);

  return 0;
}



int MatchRetValFromDifferentFunction() {

   TCHAR szPath[MAX_PATH];
   if( !GetModuleFileName( Func2(), szPath, MAX_PATH ) ) {
     printf("Cannot install service (%d)\n", GetLastError());
     return 1;
   }
   printf("Current module: %s\n", szPath);
   return 0;
}

HMODULE Func2() {
  HMODULE h = Func();
  if (h != NULL)
    return h;
  return NULL;
}


HMODULE Func() {
  return GetModuleHandle(0);
}

int MatchRetValDirect() {

   TCHAR szPath[MAX_PATH];
   if( !GetModuleFileName( GetModuleHandle(0), szPath, MAX_PATH ) ) {
     printf("Cannot install service (%d)\n", GetLastError());
     return 1;
   }
   printf("Current module: %s\n", szPath);
   return 0;
}

int Check2(HANDLE h1) {
  if (h1 == 0) return 0;
  return true;
}

int MatchRetValInLocalVar() {

  HMODULE rh = GetModuleHandle(0);

  Check2(rh);

  TCHAR szPath[MAX_PATH];
  if( !GetModuleFileName( rh, szPath, MAX_PATH ) ) {
    return 1;
  }

  return 0;
}

int MatchRetValFromDifferentFunctionV2() {
  HMODULE rh = Func2();

  Check2(rh);

  TCHAR szPath[MAX_PATH];
  if( !GetModuleFileName( rh, szPath, MAX_PATH ) ) {
    return 1;
  }

  return 0;
}

int RetvalNoMatch() {

  HANDLE h = GetCurrentProcess();
  TerminateProcess((HANDLE)0,1);
  return 0;
}

int MultiParamTest() {

  HKEY hk;
  DWORD dwDisp;
  TCHAR dwData[40];
  size_t size = sizeof(PDWORD);

  if (size<0) return 1;

  const char * val = "Val";

  RegCreateKeyEx(HKEY_CURRENT_USER,
                 "",
                 0,
                 NULL,
                 REG_OPTION_NON_VOLATILE,
                 KEY_WRITE,
                 NULL,
                 &hk,
                 &dwDisp);


  LONG res = RegSetValueEx(hk,
                           val,
                           0,
                           REG_DWORD,
                           (PBYTE)&dwData,
                           size);
  while (res < 0) {
     RegSetValueEx(hk,
                   val,
                   0,
                   REG_DWORD,
                   (PBYTE)&dwData,
                   size);
  }
}


int OutFunc(HANDLE *r, HANDLE *w) {
  SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, true};
  if(!CreatePipe(r, w, &sa, 0)) {
    return 1;
  }
  return 0;
}


int OutParamMatchInter() {

 //Variable Decle
  HANDLE stdinRd, stdinWr;
  DWORD stuff;
  char buff[1000];

  OutFunc(&stdinRd,&stdinWr);

  ReadFile(stdinRd, buff, 1000, &stuff, NULL);

  WriteFile(stdinWr,buff,1000, &stuff,NULL);

  return 0;
}

int OutFunc2(HANDLE *r, HANDLE *w) {
  char buff[1000];
  DWORD stuff;

  SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, true};
  if(!CreatePipe(r, w, &sa, 0)) {
    return 1;
  }

  ReadFile(r, buff, 1000, &stuff, NULL);
  return 0;
}

int DoClose(HANDLE h) {
  CloseHandle(h);
  return 0;
}

int OutParamMatchInterV2() {

//Variable Decle
  HANDLE stdinRd, stdinWr;
  DWORD stuff;
  char buff[1000];

  OutFunc2(&stdinRd,&stdinWr);

  WriteFile(stdinWr,buff,1000, &stuff,NULL);

  DoClose(stdinWr);

  DoClose(stdinRd);

  return 0;
}

int check3(HMODULE rh) {
  TCHAR szPath[MAX_PATH];
  if( !GetModuleFileName( rh, szPath, MAX_PATH ) ) {
    return 1;
  }
  return 0;
}

int OutParamMatchInterV3() {
  HMODULE rh = Func2();

  check3(rh);

  CloseHandle(rh);

  return 0;
}


int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszArgument, int nCmdShow) {

  ArgSameProc();
  ArgInterprocedural();
  ArgNoMatch();
  OutParamMatchIntra();

  MatchRetValDirect();
  MatchRetValInLocalVar();
  MatchRetValFromDifferentFunction();
  MatchRetValFromDifferentFunctionV2();

  RetvalNoMatch();
  MultiParamTest();
  OutParamMatchInter();

  OutParamMatchInterV2();
  OutParamMatchInterV3();

  return 0;
}




