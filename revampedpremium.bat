@echo off
title aat premium
color 4
:: Require admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Please run this batch file as Administrator.
    pause
    exit /b
)

:menu
color 7
cls
echo.
echo.  ================== [GB TWEAKS -VERSION 1.1] ==================
echo.  ========================[ Main Menu ]=========================
echo.  
echo.  tweaks:                                    RECCOMENDED:
echo. [1] all(dont work im to lazy)               [6] system restore
echo                                            
echo                                              [8] credits
echo. [2] Run service disable Script                          
echo.                                             [9] reccomended software
echo. [3] delay tweaks  
echo.
echo. [4] app deleter                    
echo.                                                
echo. [5] power plan                             [7]socials pls follow me
echo.                               
echo.   
echo.                                             
                                 
  set /p choice=Choose an option (1-9): 

if "%choice%"=="1" goto allfree
if "%choice%"=="2" goto servicedisablefree
if "%choice%"=="3" goto delaytweaks 
if "%choice%"=="4" goto appdeleter
if "%choice%"=="5" goto powerplan
if "%choice%"=="6" goto system
if "%choice%"=="7" goto socials
if "%choice%"=="8" goto credits
if "%choice%"=="9" goto softwarereccomend
:allfree

:servicedisablefree
sc config HomeGroupListener start=demand >nul 2>&1
sc config HomeGroupProvider start=demand >nul 2>&1
echo [SC] ChangeServiceConfig SUCCESS
echo [SC] ChangeServiceConfig SUCCESS
sc config p2psvc start=demand
sc config perceptionsimulation start=demand
sc config pla start=demand
sc config seclogon start=demand
sc config shpamsvc start=disabled
sc config smphost start=disabled
sc config spectrum start=demand
sc config sppsvc start=delayed-auto >nul 2>&1 
sc config ssh-agent start=disabled
sc config svsvc start=demand
sc config swprv start=demand
sc config tiledatamodelsvc start=auto >nul 2>&1 
sc config tzautoupdate start=disabled
sc config uhssvc start=disabled >nul 2>&1 
sc config upnphost start=demand
sc config vds start=demand
sc config vm3dservice start=demand >nul 2>&1 
sc config vmicguestinterface start=demand
sc config vmicheartbeat start=demand
sc config vmickvpexchange start=demand
sc config vmicrdv start=demand
sc config vmicshutdown start=demand
sc config vmictimesync start=demand
sc config vmicvmsession start=demand
sc config vmicvss start=demand
sc config vmvss start=demand >nul 2>&1 
sc config wbengine start=demand
sc config wcncsvc start=demand
sc config webthreatdefsvc start=demand
sc config webthreatdefusersvc_dc2a4 start=auto >nul 2>&1 
sc config wercplsupport start=demand
sc config wisvc start=demand
sc config wlidsvc start=demand
sc config wlpasvc start=demand
sc config wmiApSrv start=demand
sc config workfolderssvc start=demand
sc config wscsvc start=delayed-auto >nul 2>&1 
sc config wuauserv start=demand
sc config wudfsvc start=demand >nul 2>&1
sc config DisplayEnhancementService start=demand
sc config DmEnrollmentSvc start=demand
sc config Dnscache start=auto >nul 2>&1 
sc config DoSvc start=delayed-auto >nul 2>&1 
sc config DsSvc start=demand
sc config DsmSvc start=demand
sc config DusmSvc start=auto
sc config EFS start=demand
sc config EapHost start=demand
sc config EntAppSvc start=demand >nul 2>&1 
sc config EventLog start=auto
sc config EventSystem start=auto
sc config FDResPub start=demand
sc config Fax start=demand >nul 2>&1 
sc config FontCache start=auto
sc config FrameServer start=demand
sc config FrameServerMonitor start=demand
sc config GraphicsPerfSvc start=demand
sc config HomeGroupListener start=demand >nul 2>&1 
sc config HomeGroupProvider start=demand >nul 2>&1 
sc config HvHost start=demand
sc config IEEtwCollectorService start=demand >nul 2>&1 
sc config IKEEXT start=demand
sc config InstallService start=demand
sc config InventorySvc start=demand
sc config IpxlatCfgSvc start=demand
sc config KeyIso start=auto
sc config KtmRm start=demand
sc config LSM start=auto >nul 2>&1 
sc config LanmanServer start=auto
sc config LanmanWorkstation start=auto
sc config LicenseManager start=demand
sc config LxpSvc start=demand
sc config MSDTC start=disabled
sc config MSiSCSI start=demand
sc config MapsBroker start=delayed-auto
sc config McpManagementService start=demand
sc config MessagingService_dc2a4 start=demand >nul 2>&1 
sc config MicrosoftEdgeElevationService start=demand
sc config MixedRealityOpenXRSvc start=demand >nul 2>&1 
sc config MpsSvc start=auto >nul 2>&1 
sc config MsKeyboardFilter start=demand >nul 2>&1 
sc config NPSMSvc_dc2a4 start=demand >nul 2>&1 
sc config NaturalAuthentication start=demand
sc config NcaSvc start=demand
sc config NcbService start=demand
sc config NcdAutoSetup start=demand
sc config NetSetupSvc start=demand
sc config NetTcpPortSharing start=disabled
sc config Netlogon start=demand
sc config Netman start=demand
sc config NgcCtnrSvc start=demand >nul 2>&1 
sc config NgcSvc start=demand >nul 2>&1 
sc config NlaSvc start=demand
sc config OneSyncSvc_dc2a4 start=auto >nul 2>&1 
sc config P9RdrService_dc2a4 start=demand >nul 2>&1 
sc config PNRPAutoReg start=demand
sc config PNRPsvc start=demand
sc config PcaSvc start=demand
sc config PeerDistSvc start=demand >nul 2>&1 
sc config PenService_dc2a4 start=demand >nul 2>&1  
sc config PerfHost start=demand
sc config PhoneSvc start=demand
sc config PimIndexMaintenanceSvc_dc2a4 start=demand >nul 2>&1 
sc config PlugPlay start=demand
sc config PolicyAgent start=demand
sc config Power start=auto
sc config PrintNotify start=demand
sc config PrintWorkflowUserSvc_dc2a4 start=demand >nul 2>&1 
sc config ProfSvc start=auto
sc config PushToInstall start=demand
sc config QWAVE start=demand
sc config RasAuto start=demand
sc config RasMan start=demand
sc config RemoteAccess start=disabled
sc config RemoteRegistry start=disabled
sc config RetailDemo start=demand
sc config RmSvc start=demand
sc config RpcEptMapper start=auto >nul 2>&1 
sc config RpcLocator start=demand
sc config RpcSs start=auto >nul 2>&1 
sc config SCPolicySvc start=demand
sc config SCardSvr start=demand
sc config SDRSVC start=demand
sc config SEMgrSvc start=demand
sc config SENS start=auto
sc config SNMPTRAP start=demand
sc config SNMPTrap start=demand
sc config SSDPSRV start=demand
sc config SamSs start=auto
sc config ScDeviceEnum start=demand
sc config Schedule start=auto >nul 2>&1 
sc config SecurityHealthService start=demand >nul 2>&1 
sc config Sense start=demand >nul 2>&1 
sc config SensorDataService start=demand
sc config SensorService start=demand
sc config SensrSvc start=demand
sc config SessionEnv start=demand
sc config SgrmBroker start=auto >nul 2>&1 
sc config SharedAccess start=demand
sc config SharedRealitySvc start=demand
sc config ShellHWDetection start=auto
sc config SmsRouter start=demand
sc config Spooler start=auto
sc config SstpSvc start=demand
sc config StateRepository start=demand >nul 2>&1 
sc config StiSvc start=demand
sc config StorSvc start=demand
sc config SysMain start=auto
sc config SystemEventsBroker start=auto >nul 2>&1 
sc config TabletInputService start=demand >nul 2>&1 
sc config TapiSrv start=demand
sc config TermService start=auto
sc config TextInputManagementService start=demand >nul 2>&1 
sc config Themes start=auto
sc config TieringEngineService start=demand
sc config TimeBroker start=demand >nul 2>&1 
sc config TimeBrokerSvc start=demand >nul 2>&1 
sc config TokenBroker start=demand
sc config TrkWks start=auto
sc config TroubleshootingSvc start=demand
sc config TrustedInstaller start=demand
sc config UI0Detect start=demand >nul 2>&1 
sc config UdkUserSvc_dc2a4 start=demand >nul 2>&1 
sc config UevAgentService start=disabled >nul 2>&1 
sc config UmRdpService start=demand
sc config UnistoreSvc_dc2a4 start=demand >nul 2>&1 
sc config UserDataSvc_dc2a4 start=demand >nul 2>&1 
sc config UserManager start=auto
sc config UsoSvc start=demand
sc config VGAuthService start=auto >nul 2>&1 
sc config VMTools start=auto >nul 2>&1 
sc config VSS start=demand
sc config VacSvc start=demand
sc config VaultSvc start=auto
sc config W32Time start=demand
sc config WEPHOSTSVC start=demand
sc config WFDSConMgrSvc start=demand
sc config WMPNetworkSvc start=demand >nul 2>&1 
sc config WManSvc start=demand
sc config WPDBusEnum start=demand
sc config WSService start=demand >nul 2>&1 
sc config WSearch start=delayed-auto
sc config WaaSMedicSvc start=demand >nul 2>&1 
sc config WalletService start=demand
sc config WarpJITSvc start=demand
sc config WbioSrvc start=demand
sc config Wcmsvc start=auto
sc config WcsPlugInService start=demand >nul 2>&1 
sc config WdNisSvc start=demand >nul 2>&1 
sc config WdiServiceHost start=demand
sc config WdiSystemHost start=demand
sc config WebClient start=demand
sc config Wecsvc start=demand
sc config WerSvc start=demand
sc config WiaRpc start=demand
sc config WinDefend start=auto >nul 2>&1
sc config WinHttpAutoProxySvc start=demand >nul 2>&1 
sc config WinRM start=demand
sc config Winmgmt start=auto
sc config WlanSvc start=auto
sc config WpcMonSvc start=demand
sc config WpnService start=demand
sc config WpnUserService_dc2a4 start=auto >nul 2>&1 
sc config WwanSvc start=demand
sc config XblAuthManager start=demand
sc config XblGameSave start=demand
sc config XboxGipSvc start=demand
sc config XboxNetApiSvc start=demand
sc config autotimesvc start=demand
sc config bthserv start=demand
sc config camsvc start=demand
sc config cbdhsvc_dc2a4 start=demand >nul 2>&1 
sc config cloudidsvc start=demand >nul 2>&1 
sc config dcsvc start=demand
sc config defragsvc start=demand
sc config diagnosticshub.standardcollector.service start=demand
sc config diagsvc start=demand
sc config dmwappushservice start=demand
sc config dot3svc start=demand
sc config edgeupdate start=demand
sc config edgeupdatem start=demand
sc config embeddedmode start=demand >nul 2>&1 
sc config fdPHost start=demand
sc config fhsvc start=demand
sc config gpsvc start=auto >nul 2>&1 
sc config hidserv start=demand
sc config icssvc start=demand
sc config iphlpsvc start=auto
sc config lfsvc start=demand
sc config lltdsvc start=demand
sc config lmhosts start=demand
sc config mpssvc start=auto >nul 2>&1 
sc config msiserver start=demand >nul 2>&1 
sc config netprofm start=demand
sc config nsi start=auto
sc config p2pimsvc start=demand 
sc config AJRouter start=disabled
sc config ALG start=demand
sc config AppIDSvc start=demand >nul 2>&1 
sc config AppMgmt start=demand >nul 2>&1 
sc config AppReadiness start=demand
sc config AppVClient start=disabled >nul 2>&1 
sc config AppXSvc start=demand >nul 2>&1 
sc config Appinfo start=demand
sc config AssignedAccessManagerSvc start=disabled >nul 2>&1 
sc config AudioEndpointBuilder start=auto
sc config AudioSrv start=auto
sc config Audiosrv start=auto
sc config AxInstSV start=demand
sc config BDESVC start=demand >nul 2>&1 
sc config BFE start=auto >nul 2>&1 
sc config BITS start=delayed-auto
sc config BTAGService start=demand
sc config BcastDVRUserService_dc2a4 start=demand >nul 2>&1           
sc config BluetoothUserService_dc2a4 start=demand >nul 2>&1 
sc config BrokerInfrastructure start=auto >nul 2>&1 
sc config Browser start=demand >nul 2>&1 
sc config BthAvctpSvc start=auto
sc config BthHFSrv start=auto >nul 2>&1 
sc config CDPSvc start=demand
sc config CDPUserSvc_dc2a4 start=auto >nul 2>&1 
sc config COMSysApp start=demand
sc config CaptureService_dc2a4 start=demand >nul 2>&1 
sc config CertPropSvc start=demand
sc config ClipSVC start=demand >nul 2>&1 
sc config ConsentUxUserSvc_dc2a4 start=demand >nul 2>&1 
sc config CoreMessagingRegistrar start=auto >nul 2>&1 
sc config CredentialEnrollmentManagerUserSvc_dc2a4 start=demand >nul 2>&1 
sc config CryptSvc start=auto
sc config CscService start=demand >nul 2>&1 
sc config DPS start=auto
sc config DcomLaunch start=auto >nul 2>&1 
sc config DcpSvc start=demand >nul 2>&1 
sc config DevQueryBroker start=demand
sc config DeviceAssociationBrokerSvc_dc2a4 start=demand >nul 2>&1 
sc config DeviceAssociationService start=demand
sc config DeviceInstall start=demand
sc config DevicePickerUserSvc_dc2a4 start=demand >nul 2>&1 
sc config DevicesFlowUserSvc_dc2a4 start=demand >nul 2>&1 
sc config Dhcp start=auto
sc config DiagTrack start=disabled
sc config DialogBlockingService start=disabled >nul 2>&1 
sc config DispBrokerDesktopSvc start=auto 
echo  Disabling more Services..
timeout 1 > nul
sc config ALG start=disabled
sc config AJRouter start=disabled
sc config XblAuthManager start=disabled
sc config XblGameSave start=disabled
sc config XboxNetApiSvc start=disabled
sc config WSearch start=disabled
sc config lfsvc start=disabled
sc config RemoteRegistry start=disabled
sc config WpcMonSvc start=disabled
sc config SEMgrSvc start=disabled
sc config SCardSvr start=disabled
sc config Netlogon start=disabled
sc config CscService start=disabled >nul 2>&1 
sc config icssvc start=disabled 
sc config wisvc start=disabled 
sc config RetailDemo start=disabled 
sc config WalletService start=disabled 
sc config Fax start=disabled >nul 2>&1 
sc config WbioSrvc start=disabled 
sc config iphlpsvc start=disabled 
sc config wcncsvc start=disabled 
sc config fhsvc start=disabled 
sc config PhoneSvc start=disabled 
sc config seclogon start=disabled 
sc config FrameServer start=disabled 
sc config WbioSrvc start=disabled 
sc config StiSvc start=disabled 
sc config PcaSvc start=disabled 
sc config DPS start=disabled 
sc config MapsBroker start=disabled 
sc config bthserv start=disabled 
sc config BDESVC start=disabled >nul 2>&1
sc config BthAvctpSvc start=disabled 
sc config WpcMonSvc start=disabled 
sc config DiagTrack start=disabled 
sc config CertPropSvc start=disabled 
sc config WdiServiceHost start=disabled 
sc config lmhosts start=disabled 
sc config WdiSystemHost start=disabled 
sc config TrkWks start=disabled 
sc config WerSvc start=disabled 
sc config TabletInputService start=disabled >nul 2>&1 
sc config EntAppSvc start=disabled >nul 2>&1
sc config Spooler start=disabled 
sc config BcastDVRUserService start=disabled 
sc config WMPNetworkSvc start=disabled >nul 2>&1
sc config diagnosticshub.standardcollector.service start=disabled
sc config DmEnrollmentSvc start=disabled 
sc config PNRPAutoReg start=disabled 
sc config wlidsvc start=disabled 
sc config AXInstSV start=disabled 
sc config lfsvc start=disabled 
sc config NcbService start=disabled 
sc config DeviceAssociationService start=disabled
sc config StorSvc start=disabled 
sc config TieringEngineService start=disabled 
sc config DPS start=disabled 
sc config Themes start=disabled 
sc config AppReadiness start=disabled 
sc config edgeupdate start=disabled >nul 2>&1
sc config edgeupdatem start=disabled >nul 2>&1
sc config GoogleChromeElevationService start=disabled >nul 2>&1
sc config gupdate start=disabled >nul 2>&1
sc config gupdatem start=disabled >nul 2>&1
sc config BraveElevationService start=disabled >nul 2>&1
sc config brave start=disabled >nul 2>&1
sc config bravem start=disabled >nul 2>&1
echo  Services disabled successfully.

echo Disabling Hyper-V Services.
sc config HvHost start=disabled 
sc config vmickvpexchange start=disabled 
sc config vmicguestinterface start=disabled
sc config vmicvmsession start=disabled 
sc config vmicrdv start=disabled 
sc config vmictimesync start=disabled 
sc config vmicvss start=disabled 
sc config vmicshutdown start=disabled 
sc config vmicheartbeat start=disabled
echo script done.
timeout /t 2
goto menu

:delaytweaks

echo Downloading repository ZIP...
powershell -Command "Invoke-WebRequest -Uri https://github.com/SigmaGabbe/freetweakstools/archive/refs/heads/main.zip -OutFile C:\freetweakstools.zip"
echo Extracting ZIP...
powershell -Command "Expand-Archive -Path C:\freetweakstools.zip -DestinationPath C:\ -Force"
echo Done! starting script!
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ApplicationFrameHost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dllhost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\fontdrvhost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\services.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sihost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "MinimumStackCommitInBytes" /t REG_DWORD /d "32768" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wininit.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winlogon.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WMIADAP.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WmiPrvSE.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
echo Windows Processes Priority appiled successfully.
timeout 1 > nul 

cls
color D
echo grouping svchost processes.
for /f %%a in ('powershell -Command "(Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb"') do set "ram_kb=%%a"
powershell -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'SvcHostSplitThresholdInKB' -Type DWord -Value %ram_kb% -Force"
echo The operation completed successfully.
echo Svchost Processes grouped successfully.
timeout 1 > nul
bcdedit /deletevalue useplatformclock >nul 2>&1
bcdedit /set useplatformtick no
bcdedit /set disabledynamictick yes
timeout 1 > nul
echo  Setting Priority Sep. 
echo.
chcp 65001 >nul 2>&1
echo ------------------------
echo     42 Recommended.       
echo.  --------------------
echo Choose an option:
echo 1. 20 Decimal 
echo 2. 22 Decimal 
echo 3. 24 Decimal 
echo 4. 26 Decimal 
echo 5. 36 Decimal 
echo 6. 38 Decimal 
echo 7. 42 Decimal 
echo 8. Skip!
chcp 437 >nul
set /p option="Enter option number: "
echo.
if "%option%"=="1" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000014 /f
echo 20 Decimal aka 14 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="2" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000016 /f
echo 22 Decimal aka 16 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="3" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000018 /f
echo 24 Decimal aka 18 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="4" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x1a /f
echo 26 Decimal aka 1A Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="5" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000024 /f
echo 36 Decimal aka 24 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="6" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000026 /f
echo 38 Decimal aka 26 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="7" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x2a /f
echo 42 Decimal aka 2A Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul 
) else if "%option%"=="8" (
echo Skipping Priority Separation Selection!
timeout 1 > nul  
goto :SkippingPriority 
) else (
cls
chcp 437 >nul
powershell -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor black -BackgroundColor Red"
timeout 1 > nul
goto :prioritysep
)
:prioritysep
cls
color D
echo  Setting Priority Sep
echo.
chcp 65001 >nul 2>&1
echo ------------------------
echo     42 Recommended.       
echo. --------------------
echo Choose an option:
echo 1. 20 Decimal 
echo 2. 22 Decimal 
echo 3. 24 Decimal 
echo 4. 26 Decimal 
echo 5. 36 Decimal 
echo 6. 38 Decimal 
echo 7. 42 Decimal 
echo 8. Skip!
chcp 437 >nul
set /p option="Enter option number: "
echo.
if "%option%"=="1" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000014 /f
echo 20 Decimal aka 14 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="2" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000016 /f
echo 22 Decimal aka 16 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="3" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000018 /f
echo 24 Decimal aka 18 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="4" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x1a /f
echo 26 Decimal aka 1A Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="5" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000024 /f
echo 36 Decimal aka 24 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="6" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x00000026 /f
echo 38 Decimal aka 26 Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul
) else if "%option%"=="7" (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x2a /f
echo 42 Decimal aka 2A Hexadecimal, Priority Separation appiled successfully.
timeout 1 > nul 
) else if "%option%"=="8" (
echo Skipping Priority Separation Selection!
timeout 1 > nul  
goto :SkippingPriority 
) else (
cls
chcp 437 >nul
powershell -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor black -BackgroundColor Red"
timeout 1 > nul
goto :SettingPrioritySeparation
)

:SkippingPriority
cls
color 9
echo  Installing Visual C++ 2015-2022 Redistributable
echo.
:: Check if Visual C++ 2015-2022 Redistributable (x64) is installed
reg query "HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" > nul 2>&1
if %errorlevel% == 0 (
    echo Visual C++ 2015-2022 Redistributable is installed
    timeout 1 > nul
    goto :WinVerD
) else (
    echo Visual C++ 2015-2022 Redistributable is not installed
    timeout 1 > nul
    goto :VCRuntime
)
pause

:VCRuntime
:: Download VC++ Redistributable
set "fileURL=https://aka.ms/vs/17/release/vc_redist.x64.exe"
set "fileName=VC_redist.x64.exe"
mkdir "C:\Delay Destroyer Tools\VC Redist" >nul 2>&1
set "downloadsFolder=C:\freetweakstools.main\VC Redist"
chcp 65001 >nul 2>&1
echo.
echo ╔═════════════════════════════╗
echo ║                             ║
echo ║    Downloading resources    ║
echo ║                             ║
echo ╚═════════════════════════════╝
chcp 437 >nul
curl -s -L "%fileURL%" -o "%downloadsFolder%\%fileName%"

:: Check if the file was downloaded successfully
if exist "%downloadsFolder%\%fileName%" (
    echo File downloaded successfully.
    echo.
    echo Starting Visual C++ 2015-2022 Redistributable...
    start "" "%downloadsFolder%\%fileName%"
    echo.
    echo Please install the redistributable package to continue.
    echo Once installed, click "Install" to proceed or close to cancel...
    echo.
    pause
) else (
    echo Failed to download the file.
    timeout 1 > nul
    goto :VCRuntime
)

:WinVerD
:: Check Windows version and build
for /f "tokens=3" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v "CurrentBuild" 2^>nul ^| findstr /i "CurrentBuild"') do (
    set "build_num=%%A"
)

if not defined build_num (
    echo Failed to detect Windows build. Exiting...
    timeout 3 > nul
    endlocal
    exit /b
)

:: Windows 11: build 22000+
if !build_num! GEQ 22000 (
    endlocal
    goto :TimerRes11
)

:: Windows 10 20H2 (19042+) and above
if !build_num! GEQ 19042 (
    endlocal
    goto :TimerRes10
)

:: Older Windows 10 or unsupported
endlocal
goto :TimerRes11

:TimerRes10
cls
color D
chcp 65001 >nul
echo Timer Resolution.
echo.
echo ╔═════════════════════════════╗
echo ║     0.504ms Recommended!    ║
echo ╚═════════════════════════════╝
echo      use lower if u want.
chcp 437 >nul
echo.
echo Choose an option:
echo 1. Timer Res 0.500ms
echo 2. Timer Res 0.502ms
echo 3. Timer Res 0.504ms
echo 4. Timer Res 0.507ms

set /p option="Enter option number: "
if "%option%"=="1" (
    call :ApplyTimerRes "5000"
) else if "%option%"=="2" (
    call :ApplyTimerRes "5020"
) else if "%option%"=="3" (
    call :ApplyTimerRes "5040"
) else if "%option%"=="4" (
    call :ApplyTimerRes "5070"
) else (
    cls
    powershell -Command "Write-Host 'Invalid choice. Please select 1-4.' -ForegroundColor White -BackgroundColor Red"
    timeout 1 > nul
    goto :TimerRes10
)

goto :ndistweaks

:TimerRes11
cls
color D
rd /s /q "C:\Delay Destroyer Tools\DPC Checker" >nul 2>&1
chcp 65001 >nul
echo Timer Resolution.
echo.
echo ╔═════════════════════════════╗
echo ║     0.504ms Recommended.    ║
echo ╚═════════════════════════════╝
echo      use lower if u want.
chcp 437 >nul
echo.
echo Choose an option:
echo 1. Timer Res 0.500ms
echo 2. Timer Res 0.502ms
echo 3. Timer Res 0.504ms
echo 4. Timer Res 0.507ms
echo 5. Skip!

set /p option="Enter option number: "
if "%option%"=="1" (
    call :ApplyTimerRes "5000"
) else if "%option%"=="2" (
    call :ApplyTimerRes "5020"
) else if "%option%"=="3" (
    call :ApplyTimerRes "5040"
) else if "%option%"=="4" (
    call :ApplyTimerRes "5070"
) else if "%option%"=="5" (
    echo.
    echo Skipping Timer Resolution Selection!
    timeout 1 > nul
) else (
    cls
    powershell -Command "Write-Host 'Invalid choice. Please select 1-5.' -ForegroundColor White -BackgroundColor Red"
    timeout 1 > nul
    goto :TimerRes11
)

goto :ndistweaks

:ApplyTimerRes
:: %~1 = resolution value
echo.
echo Adding TimerResolution to startup!
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "TimerResolution" /t REG_SZ /d "C:\Delay Destroyer Tools\Timer Resolution\SetTimerResolution.exe --resolution %~1 --no-console" /f
echo.
echo Starting TimerResolution...
start "" "C:\Delay Destroyer Tools\Timer Resolution\SetTimerResolution.exe" --resolution %~1 --no-console
echo Timer Res is now active in the background!

:: Only on Win10 path: also start DPC Checker
if /i "%build_num%" LSS "22000" (
    echo.
    echo Adding Win 10 TimerRes Fix/DPC Checker to startup!
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "DPC Checker" /t REG_SZ /d "C:\Delay Destroyer Tools\DPC Checker\dpclat.exe" /f
    echo.
    echo Starting DPC Checker...
    powershell -Command "Write-Host 'Click *Stop* and then *Minimize* every time you restart your PC.' -ForegroundColor White -BackgroundColor Red"
    start "" "C:\Delay Destroyer Tools\DPC Checker\dpclat.exe"
    echo DPC Checker is now active in the background!
)

timeout 1 > nul
exit /b

:ndistweaks

echo do you want to run NDIS tweaks?
echo not reccomended if not used restore point. can cause network issues buyt improve latenccy on NDIS driver.
set /p choice=Enter (Y/N): 
f /i "%choice%"=="Y" (
    timeout 1 > nul
    cls
    goto :NDIS
) else if /i "%choice%"=="N" ( 
    timeout 1 > nul
    cls
    goto :DMT
:NDIS
cls
setlocal
echo Detecting Network Adapter.

for /f "skip=1 delims=" %%a in ('wmic nic where "NetConnectionStatus=2" get NetConnectionID /value 2^>nul') do (
    for /f "tokens=2 delims==" %%b in ("%%a") do (
        set "adapter_name=%%b"
    )
)

if defined adapter_name (
    echo Your current network adapter is: %adapter_name%

    echo Enabling Interrupt Moderation and setting Interrupt Moderation Rate to medium.
    powershell -Command "Get-NetAdapterAdvancedProperty -Name \"%adapter_name%\" -DisplayName 'Interrupt Moderation' | Set-NetAdapterAdvancedProperty -RegistryValue 1" >nul 2>&1
    powershell -Command "Get-NetAdapterAdvancedProperty -Name \"%adapter_name%\" -DisplayName 'Interrupt Moderation Rate' | Set-NetAdapterAdvancedProperty -RegistryValue 125" >nul 2>&1

    echo Setting NetworkThrottlingIndex to 10.
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 10 /f
    echo NDIS Tweaks appiled successfully.
    timeout 1 > nul
) else (
    echo Unable to detect your current network adapter.
    echo Skipping.
    timeout 1 > nul
)
endlocal

:DMT
cls
color D
echo Do you want to Run  Device Manager Tweaks?
echo.
chcp 437 >nul
powershell -Command "Write-Host '(Not Recommended) Can cause bluescreens and other issues, so be cautious.' -ForegroundColor black -BackgroundColor Red"
echo.
set /p choice=Enter (Y/N): 
if /i "%choice%"=="Y" (
    timeout 1 > nul
    cls
    goto :DeviceManagerTweaks
) else if /i "%choice%"=="N" ( 
    timeout 1 > nul
    cls
    goto :disablewifidevices
) else (
    cls
    chcp 437 >nul
    powershell -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
    timeout 1 > nul
    goto :disablewifidevices
)
:DeviceManagerTweaks
echo  Disabling devices in Device Manager.
setlocal enabledelayedexpansion

:: Device Names.
set "Device[0]=Microsoft GS Wavetable Synth"
set "Device[1]=NDIS Virtual Network Adapter Enumerator"
set "Device[2]=Composite Bus Enumerator"
set "Device[3]=Microsoft Virtual Drive Enumerator"
set "Device[4]=Remote Desktop Device Redirector Bus"
set "Device[5]=Mircosoft RRAS Root Enumerator"
set "Device[6]=Mircosoft Print to PDF"
set "Device[7]=Root Print Queue"
set "Device[8]=Intel(R) Management Engine Interface #1"
set "Device[9]=Intel(R) SPI (Flash) Controller - 7AA4"
set "Device[10]=Intel(R) SMBus - 7AA3"
set "Device[11]=UMBus Root Bus Enumerator"
set "Device[12]=Microsoft Hypervisor Service"
set "Device[13]=Microsoft Device Association Root Enumerator"
set "Device[14]=Microsoft Hyper-V Vitualization Infrastucture Driver"
set "Device[15]=Bluetooth Device (RFCOMM Protocol TDI)"
set "Device[16]=Intel(R) Wireless Bluetooth(R)"
set "Device[17]=Microsoft Bluetooth Enumerator"
set "Device[18]=Microsoft Bluetooth LE Enumerator"
set "Device[19]=Bluetooth Device (Personal Area Network)"
set "Device[20]=NVIDIA High Definition Audio"

:: Loop through all devices and disable them by InstanceId
for /L %%i in (0,1,20) do (
    for /f "usebackq tokens=*" %%A in (`powershell -command "Get-PnpDevice -FriendlyName '!Device[%%i]!' | Select-Object -ExpandProperty InstanceId"`) do (
        set "instanceID=%%A"
    )
    if defined instanceID (
        echo Disabling device: !Device[%%i]! with InstanceId: !instanceID!
        pnputil /disable-device "!instanceID!" >nul 2>&1
    )
)
endlocal
timeout 1 > nul

:DisableWifiDevices
cls
echo Do you want to Disable Wifi Devices?
echo.
chcp 437 >nul
powershell -Command "Write-Host 'It Will Break Wifi' -ForegroundColor White -BackgroundColor Red"
echo.
echo Are you sure? (Y/N)
set /p option="Enter option number: "
if /i "%option%"=="Y" (
    echo.
    echo Now Disabling Wifi Devices...
    timeout 1 > nul
    cls
    goto :WifiDevice
) else if /i "%option%"=="N" (
    echo.
    echo Skipping Wifi Device Manager Tweaks...
    timeout 1 > nul
    cls
    goto :appdeleter
) else (
    cls
    chcp 437 >nul
    powershell -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
    timeout 1 > nul
    goto :DisableWifiDevices
)

:WifiDevice
echo  Disabling Wifi devices.
setlocal enabledelayedexpansion

:: Device Names.
set "Device[0]=Intel(R) Wi-Fi"
set "Device[1]=WAN Miniport (IKEv2)"
set "Device[2]=WAN Miniport (IP)"
set "Device[3]=WAN Miniport (IPv6)"
set "Device[4]=WAN Miniport (L2TP)"
set "Device[5]=WAN Miniport (Network Monitor)"
set "Device[6]=WAN Miniport (PPPOE)"
set "Device[7]=WAN Miniport (PPTP)"
set "Device[8]=WAN Miniport (SSTP)"

:: Loop through all devices and disable them by InstanceId
for /L %%i in (0,1,8) do (
    for /f "usebackq tokens=*" %%A in (`powershell -command "Get-PnpDevice -FriendlyName '!Device[%%i]!' | Select-Object -ExpandProperty InstanceId"`) do (
        set "instanceID=%%A"
    )
    if defined instanceID (
        echo Disabling device: !Device[%%i]! with InstanceId: !instanceID!
        pnputil /disable-device "!instanceID!" >nul 2>&1
    )
)
endlocal
timeout 1 > nul

goto appdeleter


:appdeleter
echo wstore and xbox are options!
set /p answer=Do you want to delete all windows apps? (Y/N): 


set answer=%answer:~0,1%
if /I "%answer%"=="Y" (
    goto continueedelete
) else if /I "%answer%"=="N" (
    goto powerplan
) else (
    echo Invalid input. Please enter Y or N.
    goto appdeleter
)





:end
pause

:continueedelete
echo You chose Yes. Running delete apps.
:: Remove stock Windows apps
echo Removing stock Windows apps (except Xbox and Store)...
powershell -command "Get-AppxPackage | Remove-AppxPackage"
powershell -command "Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online"

:: Ask about Xbox
echo.
choice /M "Do you want to remove Xbox apps?"
if errorlevel 2 goto xbox_keep
if errorlevel 1 goto xbox_remove

:xbox_remove
echo Removing Xbox apps...
powershell -command "Get-AppxPackage *Xbox* | Remove-AppxPackage"
powershell -command "Get-AppxProvisionedPackage -Online | where DisplayName -like '*Xbox*' | Remove-AppxProvisionedPackage -Online"
goto store_prompt

:xbox_keep
echo Keeping Xbox apps and starting related services...
net start XblAuthManager >nul 2>&1
net start XblGameSave >nul 2>&1
net start XboxNetApiSvc >nul 2>&1
net start XboxGipSvc >nul 2>&1

:: Ask about Store
:store_prompt
echo.
choice /M "Do you want to remove Microsoft Store app?"
if errorlevel 2 goto store_keep
if errorlevel 1 goto store_remove

:store_remove
echo Removing Microsoft Store app...
powershell -command "Get-AppxPackage *WindowsStore* | Remove-AppxPackage"
powershell -command "Get-AppxProvisionedPackage -Online | where DisplayName -like '*WindowsStore*' | Remove-AppxProvisionedPackage -Online"
goto powerplan

:store_keep
echo Keeping Microsoft Store app and starting related services...
net start ClipSVC >nul 2>&1
net start AppXSvc >nul 2>&1
goto powerplan

:end
echo.
echo Done.
goto powerplan

:powerplan
cls

echo [1] 100%% powerplan
echo [2] revert (normal powerplan)
echo [3] exit to menu
set /p choice=Choose an option (1-3): 
if "%choice%"=="1" goto 100
if "%choice%"=="2" goto revert100
if "%choice%"=="3" goto menu

:100
cls
setlocal enabledelayedexpansion

:: Step 1: Duplicate the High Performance power scheme
for /f "tokens=3" %%a in ('powercfg -list ^| findstr /i "High performance"') do (
    set GUID=%%a
    powercfg -duplicatescheme !GUID!
)

:: Step 2: Get the last added GUID
for /f "tokens=3" %%b in ('powercfg -list ^| findstr /i "Power Scheme GUID"') do (
    set LAST_GUID=%%b
)

:: Step 3: Rename the plan
powercfg -changename !LAST_GUID! "aat 100%%"

:: Step 4: Set it as active
powercfg -setactive !LAST_GUID!

:: Step 5: Turn off sleep (AC and DC)
powercfg -setacvalueindex !LAST_GUID! SUB_SLEEP STANDBYIDLE 0
powercfg -setdcvalueindex !LAST_GUID! SUB_SLEEP STANDBYIDLE 0

:: Step 6: Set min and max processor state to 100% (AC and DC)
powercfg -setacvalueindex !LAST_GUID! SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg -setacvalueindex !LAST_GUID! SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg -setdcvalueindex !LAST_GUID! SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg -setdcvalueindex !LAST_GUID! SUB_PROCESSOR PROCTHROTTLEMAX 100

:: Step 7: Apply changes
powercfg -S !LAST_GUID!

echo.
echo Power plan "aat 100%%" created, configured, and set as active.
pause
endlocal
goto :eof

:revert100
:revert100
cls
echo Reverting to the default Balanced power plan...
setlocal enabledelayedexpansion

:: Step 1: Get the GUID of the Balanced plan
for /f "tokens=3" %%a in ('powercfg -list ^| findstr /i "Balanced"') do (
    set BAL_GUID=%%a
)

:: Step 2: Set it as the active plan
powercfg -setactive !BAL_GUID!

:: Step 3 (Optional): Delete the custom "aat 100%" plan
for /f "tokens=3,*" %%a in ('powercfg -list') do (
    echo %%b | findstr /i "aat 100%" >nul
    if !errorlevel! == 0 (
        powercfg -delete %%a
        echo Deleted custom plan "aat 100%%"
    )
)

echo Default Balanced plan restored and custom plan removed (if found).
pause
endlocal
goto menu

:system
cls

:: Made by Gabbe
:: here is restore point😊💕 use before tweaks if u want.
 
title SYSTEM RESTORE POINT  V1.0
color 9


chcp 65001 >nul 2>&1
echo.
echo.
echo.
echo.
echo.                           ▒███████▒ ▒█████   ▄▄▄█████▓▓█████ ▄▄▄       ▄████▄   ██ ▄█▀
echo.                           ▒ ▒ ▒ ▄▀░▒██▒  ██▒▓  ██▒ ▓▒▓█   ▀▒████▄    ▒██▀ ▀█   ██▄█▒ 
echo.                           ░ ▒ ▄▀▒░ ▒██░  ██▒▒ ▓██░ ▒░▒███  ▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ 
echo.                             ▄▀▒   ░▒██   ██░░ ▓██▓ ░ ▒▓█  ▄░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ 
echo.                           ▒███████▒░ ████▓▒░  ▒██▒ ░ ░▒████▒▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄
echo.                           ░▒▒ ▓░▒░▒░ ▒░▒░▒░   ▒ ░░   ░░ ▒░ ░▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒
echo.                           ░░▒ ▒ ░ ▒  ░ ▒ ▒░     ░     ░ ░  ░ ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░
echo.                           ░ ░ ░ ░ ░░ ░ ░ ▒    ░         ░    ░   ▒   ░        ░ ░░ ░ 
echo.                               ░ ░      ░ ░              ░  ░     ░  ░░ ░      ░  ░  
echo.
echo.                            ╔══════════════════════════════════════════════════════╗
echo.                            ║                GB TWEAKS - VERSION 1.0               ║
::echo.                          ║               Optimizations & Mods by GB             ║
echo.                            ╚══════════════════════════════════════════════════════╝
echo.
echo.
echo.
echo. 
echo. ╔═════════╗                                                                        
echo. ║ Loading ║                                              
echo. ╚═════════╝
timeout 2 > nul              

:: (Gabbe) Restore Point.
:RP
cls
color D
chcp 65001 >nul 2>&1
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.                                 ██████╗ ███████╗███████╗████████╗ ██████╗ ██████╗ ███████╗
echo.                                 ██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
echo.                                 ██████╔╝█████╗  ███████╗   ██║   ██║   ██║██████╔╝█████╗  
echo.                                 ██╔══██╗██╔══╝  ╚════██║   ██║   ██║   ██║██╔══██╗██╔══╝  
echo.                                 ██║  ██║███████╗███████║   ██║   ╚██████╔╝██║  ██║███████╗
echo.                                 ╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
echo. 
echo.                                  ╔════════════════════════════════════════════════════╗
echo.                                  ║   Create a restore point to undo system changes!   ║
echo.                                  ╚════════════════════════════════════════════════════╝
echo.
echo.
echo.
echo.                                                                       
chcp 437 >nul
powershell -Command "Write-Host 'Recommended!' -ForegroundColor White -BackgroundColor Red"
echo Do you want to make a restore point?
set /p choice=Enter (Y/N): 
if /i "%choice%"=="Y" goto yes 
 if /i "%choice%"=="N" goto no
:yes
PowerShell -Command "Checkpoint-Computer -Description 'aat restore' -RestorePointType 'MODIFY_SETTINGS'"
echo.
echo Restore point 'aat restore' created (if System Protection is enabled).
pause
goto check
:check
echo Launching System Restore check ...
start "" "C:\Windows\System32\rstrui.exe"
goto menu

:no
    echo ________________________________________________
    echo Not creating a restore point, you just wasted your time.
    timeout 2 > nul
goto menu
) else (
    cls
    powershell -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
    timeout 2 > nul
   
goto menu

:socials
cls
echo.   [1] tweak tiktok        
echo.   [2] discord 
echo.   [3] discord server
echo.   [4] my personal tiktok
echo.   [5] Exit 
echo.   [6] steam
echo.   [7] github 
echo.
set /p choice=Choose an option:

if "%choice%"=="1" goto tiktok
if "%choice%"=="2" goto discord
if "%choice%"=="3" goto server
if "%choice%"=="4" goto personal
if "%choice%"=="5" goto exit
if "%choice%"=="6" goto steam
if "%choice%"=="7" goto git

pause
goto socials

:tiktok 
start https://www.tiktok.com/@aat_tweaks_gb?lang=nb
goto socials

:discord 
echo user name is gabbegoat_ name on server is sss .
pause
goto socials

:server
start https://discord.gg/x5MpN2xS
goto socials

:personal 
start https://www.tiktok.com/@imwhitemadarfakar
goto socials

:steam 
start https://steamcommunity.com/id/mindofGabbe/
goto socials

:git
start https://github.com/SigmaGabbe
goto socials

:exit
echo Exiting to main menu...
pause
cls
goto menu

:credits
:credits
@echo off
chcp 65001 >nul 2>&1
echo.
echo.
echo.
echo.
echo.                           ▒███████▒ ▒█████   ▄▄▄█████▓▓█████ ▄▄▄       ▄████▄   ██ ▄█▀
echo.                           ▒ ▒ ▒ ▄▀░▒██▒  ██▒▓  ██▒ ▓▒▓█   ▀▒████▄    ▒██▀ ▀█   ██▄█▒ 
echo.                           ░ ▒ ▄▀▒░ ▒██░  ██▒▒ ▓██░ ▒░▒███  ▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ 
echo.                             ▄▀▒   ░▒██   ██░░ ▓██▓ ░ ▒▓█  ▄░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ 
echo.                           ▒███████▒░ ████▓▒░  ▒██▒ ░ ░▒████▒▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄
echo.                           ░▒▒ ▓░▒░▒░ ▒░▒░▒░   ▒ ░░   ░░ ▒░ ░▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒
echo.                           ░░▒ ▒ ░ ▒  ░ ▒ ▒░     ░     ░ ░  ░ ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░
echo.                           ░ ░ ░ ░ ░░ ░ ░ ▒    ░         ░    ░   ▒   ░        ░ ░░ ░ 
echo.                               ░ ░      ░ ░              ░  ░     ░  ░░ ░      ░  ░  
echo.
echo.                     ╔════════════════════════════════════════════════════════════════════════════════════════╗
echo.                     ║                GB TWEAKS - VERSION 1.2                                                 ║
echo.                     ║              to get on the credits board                                               ║
echo.                     ║       submit a tweak for me to test in discord                                         ║
echo.                     ║      credits:                                                                          ║
echo.                     ║ testers: blatanss/vio                                                                  ║
echo.                     ║ dev: gabbegoat_/sss                                                                    ║
echo.                     ║ dc mods: blatans/vio                                                                   ║
echo.                     ║ gpu tweaks : quaked.                                                                 ║                             
echo.                     ╚════════════════════════════════════════════════════════════════════════════════════════╝
echo.
echo.
echo.
echo. 
 set /p choice=Choose an option (1-1): 
if "%choice%"=="1" goto menu
pause
goto menu

:softwarereccomend
echo.[1] Driver booster
echo.[2] lossless scaling (increases delay)
echo.[3] screen recorder 
echo.[4] stix os 
set /p choice=Choose an option (1-3):
if "%choice%"=="1" start https://store.steampowered.com/app/920490/Driver_Booster_for_Steam/ 
if "%choice%"=="3" start https://screenrec.com/screenrec-quickstart-guide-for-windows-xp-vista-7-8-10/
if "%choice%"=="2" start https://store.steampowered.com/app/993090/Lossless_Scaling/
if "%choice%"=="4" start https://www.mediafire.com/file/ratfod57mlenk7b/StixOS.iso/file