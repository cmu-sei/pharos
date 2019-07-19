// Copyright 2016 Carnegie Mellon University.  See LICENSE file for terms.

// cl /EHsc  /MD ApiGraphTestProgram.cc
#include <windows.h>
#include <iostream>

int Empty() {
  int j=0;
  for (int i=0; i < 10; i++) {
    j = i*2;
  }
  return j;

}

void Func2() {
  WaitForSingleObject(INVALID_HANDLE_VALUE,INFINITE);
}

void Func1() {
  GetModuleHandle(0);
  Func2();
}

void DoRead3(HANDLE h, char buff[]) {

  DWORD stuff;
  do {
    ReadFile(h, buff, 1000, &stuff, NULL);
  } while(stuff == 1000);
  Func1();
}



void DoRead2(HANDLE h, char buff[]) {
  GetTickCount();
  DoRead3(h,buff);

}

void Func5() {
  LARGE_INTEGER li;
  QueryPerformanceCounter(&li);
}

void Func4() {
  GetTickCount();
  Func5();

}

void DoRead(HANDLE h, char buff[]) {
  DoRead2(h,buff);
  while (Empty()<10) {
    Func4();
  }
  Empty();
}

int InterProcedural() {

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

           DoRead(stdoutRd, buff);
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

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszArgument, int nCmdShow) {

  InterProcedural();

  return 0;
}




