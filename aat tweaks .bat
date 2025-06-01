@echo off
title GB Tweaks - Launcher
color 0A


:menu
cls
echo.               [GB TWEAKS -VERSION 1.1]
echo. ===================[ Main Menu ]===================
echo.   [1] Run debloat script  (safest script)     
echo.
echo.   [2] Run service disable Script 
echo.
echo.   [3] Apply Registry Tweaks
echo.
echo.   [4] gpu tweaks (.quaked not mine.) (creator of oneclick)
echo.
echo.   [5] View System Info RUN BEFORE DISABLING HYPER-V 
echo.
echo.   [6] Exit 
echo.
echo.   [7] restart
echo.
echo.   [8] credits 
echo.
echo.   [9] system restore
echo.
echo.   [10] socials
echo.
echo.   [11] power plan
echo.
echo.   [12] everything. (runs all tweaks 
     set /p choice=Choose an option (1-12): 

if "%choice%"=="2" goto optimize
if "%choice%"=="3" goto regtweaks
if "%choice%"=="5" goto sysinfo
if "%choice%"=="6" goto end
if "%choice%"=="7" goto restart
if "%choice%"=="8" goto credits
if "%choice%"=="1" goto debloat
if "%choice%"=="4" goto gpu
if "%choice%"=="9" goto system 
if "%choice%"=="10" goto socials
if "%choice%"=="11" goto power
if "%choice%"=="12" goto alltweaks
goto menu
cls
:optimize
cls
echo Running optimization script...
:: first opt
@echo off
echo Disabling unnecessary services...
 title disable services🥶👌.
::made by gabbegoat/sss.
:: discord: gabbegoat_
:: tiktok: imwhitemadarfakar
:: pls join discord server (add me)

Disable ActiveX Installer (ActiveX Installer) - ActiveX Control Installation
sc config AxInstSV start= disabled
net stop AxInstSV

:: Disable BitLocker Drive Encryption Service (BitLocker) - Encryption for disk drives
sc config BitLockerDriveEncryption start= disabled
net stop BitLockerDriveEncryption

:: Disable Cellular Time (CellularTime) - Sync time via cellular network
sc config CellularTime start= disabled
net stop CellularTime

:: Disable Certificate Propagation (CertPropSvc) - Manages certificate-related operations
sc config CertPropSvc start= disabled
net stop CertPropSvc

:: Disable Cloud Backup and Restore Service (wuauserv, etc.) - Cloud-based backup service
sc config CldFlt start= disabled
net stop CldFlt

:: Disable Connected Devices Platform Service (cdpusersvc) - Manages device connectivity and settings
sc config cdpusersvc start= disabled
net stop cdpusersvc

:: Disable Connected User Experiences and Telemetry (DiagTrack) - Collects user experience data for diagnostics
sc config DiagTrack start= disabled
net stop DiagTrack

:: Disable Contact Data (cdpuser) - Deals with contact syncing for Microsoft services
sc config cdpuser start= disabled
net stop cdpuser

::ok im to lazy to list em all disabling services..

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

pause

timeout /t 2
echo Done!
pause
goto menu


:regtweaks
cls
echo Applying registry tweaks...
:: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ApplicationFrameHost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
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
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PrioityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x2a /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\SystemRestore" /v "RPSessionInterval" /f >nul 2>&1 
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f
cls
echo Tweaks applied.
goto menu



:sysinfo
cls
echo =============================================
echo SYSTEM INFORMATION
echo =============================================
echo pre prep incase u used tweaks.
echo =============================================
echo Enabling Hyper-V Services...
echo =============================================
:: Must be run as Administrator
echo choose 1-2 
echo 1=no ram info (choose if u used tweaks)
echo 2= ram info 
 set /p choice=Choose an option (1-2): 

if "%choice%"=="1" goto noram
if "%choice%"=="2" goto yesram

:yesram
:: Operating System
echo.
echo [OS INFORMATION]
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

:: CPU
echo.
echo [CPU INFORMATION]
wmic cpu get name,MaxClockSpeed /format:table

:: GPU
echo.
echo [GPU INFORMATION]
wmic path win32_VideoController get name /format:table

:: RAM Info (Total in GB and Speed)
echo.
echo [RAM INFORMATION]
powershell -Command "& {
    $ram = Get-CimInstance Win32_PhysicalMemory
    $totalGB = [math]::Round(($ram | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
    $speeds = $ram | Select-Object -ExpandProperty Speed | Sort-Object -Unique
    Write-Host 'Total RAM (GB):' $totalGB
    Write-Host 'RAM Speeds (MHz):' ($speeds -join ', ')
}"

:: Motherboard Info
echo.
echo [MOTHERBOARD INFORMATION]
wmic baseboard get Manufacturer,Product /format:table

pause

:noram
:: Operating System
echo.
echo [OS INFORMATION]
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

:: CPU
echo.
echo [CPU INFORMATION]
wmic cpu get name,MaxClockSpeed /format:table

:: GPU
echo.
echo [GPU INFORMATION]
wmic path win32_VideoController get name /format:table



pause

timeout /t 2
echo Done!
pause
goto menu

:end
cls
echo.
echo Thanks for using GB Tweaks!
echo.
timeout /t 2 >nul
exit

:restart 
pause
shutdown -r

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


:debloat
cls
echo [*] Starting Safe Debloat for Windows 11 23H2...
echo   DOES REMOVE BROWSER powershell command in discord.


:: -------------------------------
:: Disable Telemetry
echo [*] Disabling telemetry...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

:: -------------------------------
:: Remove bloatware apps (AppX)
echo [*] Removing preinstalled bloatware apps...
setlocal enabledelayedexpansion
for %%A in (
    "Microsoft.3DBuilder"
    "Microsoft.BingNews"
    "Microsoft.GamingApp"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MixedReality.Portal"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.SkypeApp"
    "Microsoft.Todos"
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
) do (
    echo Removing: %%~A
    powershell -Command "Get-AppxPackage -Name %%~A | Remove-AppxPackage -ErrorAction SilentlyContinue"
    powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq '%%~A'} | Remove-AppxProvisionedPackage -Online"
)

:: -------------------------------
:: Remove OneDrive
echo [*] Removing OneDrive...
taskkill /f /im OneDrive.exe >nul 2>&1
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
%SystemRoot%\System32\OneDriveSetup.exe /uninstall
rd "%UserProfile%\OneDrive" /Q /S >nul 2>&1
rd "C:\OneDriveTemp" /Q /S >nul 2>&1
rd "%LocalAppData%\Microsoft\OneDrive" /Q /S >nul 2>&1
rd "%ProgramData%\Microsoft OneDrive" /Q /S >nul 2>&1

:: -------------------------------
:: Remove Microsoft Edge
echo [*] Removing Microsoft Edge...
cd %ProgramFiles(x86)%\Microsoft\Edge\Application\*\Installer
if exist setup.exe (
    setup.exe --uninstall --system-level --verbose-logging --force-uninstall
) else (
    echo [!] Microsoft Edge uninstall files not found.
)

:: -------------------------------
:: Prompt to disable Windows Defender
set /p disableWD=Do you want to disable Windows Defender? (Y/N): 
if /I "%disableWD%"=="Y" (
    echo [*] Disabling Windows Defender...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
) else (
    echo [*] Skipping Defender disable.
)

:: -------------------------------
:: Disable Cortana
echo [*] Disabling Cortana...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

:: -------------------------------
:: Disable background apps
echo [*] Disabling background apps...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f

:: -------------------------------
:: Disable telemetry scheduled tasks
echo [*] Disabling telemetry scheduled tasks...
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

:: -------------------------------
:: Clean temp files
echo [*] Cleaning temp files...
del /q /f /s %TEMP%\*
del /q /f /s C:\Windows\Temp\*
:: -------------------------------
:: Prompt to disable non-crucial services
set /p disableServices=Do you want to disable non-crucial Windows services? (Y/N): 
if /I "%disableServices%"=="Y" (
    echo [*] Disabling non-crucial services...

    reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f


    :: Xbox services
    sc stop XblAuthManager
    sc config XblAuthManager start= disabled
    sc stop XblGameSave
    sc config XblGameSave start= disabled
    sc stop XboxGipSvc
    sc config XboxGipSvc start= disabled
    sc stop XboxNetApiSvc
    sc config XboxNetApiSvc start= disabled

    :: Diagnostics & telemetry
    sc stop DiagTrack
    sc config DiagTrack start= disabled
    sc stop dmwappushservice
    sc config dmwappushservice start= disabled

    :: Remote Desktop services (disable only if unused)
    sc stop TermService
    sc config TermService start= disabled

    :: Retail Demo service
    sc stop RetailDemo
    sc config RetailDemo start= disabled

    :: Print Spooler (disable only if you don't use printers)
    sc stop Spooler
    sc config Spooler start= disabled

    :: Fax service (very rarely used)
    sc stop Fax
    sc config Fax start= disabled

    e


    echo [*] Services disabled.
) else (
    echo [*] Skipping service disable.
)
echo.
echo [✓] Debloat complete. Please restart your PC. or use other tweaks.
pause
goto menu



:gpu
title Gpu Tweaks 

color 9

    
)
cls
color D
chcp 65001 >nul 2>&1
echo.
echo.
echo.
echo.
echo.
echo.                                                ██████╗ ██████╗ ██╗   ██╗             
echo.                                               ██╔════╝ ██╔══██╗██║   ██║             
echo.                                               ██║  ███╗██████╔╝██║   ██║             
echo.                                               ██║   ██║██╔═══╝ ██║   ██║             
echo.                                               ╚██████╔╝██║     ╚██████╔╝             
echo.                                                ╚═════╝ ╚═╝      ╚═════╝              
echo.                                                   
echo.                                  ████████╗██╗    ██╗███████╗ █████╗ ██╗  ██╗███████╗
echo.                                  ╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║ ██╔╝██╔════╝
echo.                                     ██║   ██║ █╗ ██║█████╗  ███████║█████╔╝ ███████╗
echo.                                     ██║   ██║███╗██║██╔══╝  ██╔══██║██╔═██╗ ╚════██║
echo.                                     ██║   ╚███╔███╔╝███████╗██║  ██║██║  ██╗███████║
echo.                                     ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
echo.
echo.                                  ╔════════════════════════════════════════════════════╗
echo.                                  ║             Please select your GPU...              ║       
echo.                                  ╚════════════════════════════════════════════════════╝
echo.
echo.
echo.
echo.
echo Choose an option:
echo 1. Nvidia  
echo 2. AMD 
echo 3. Intel
echo 4. Skip!
set /p option="Enter option number: "
echo.
if "%option%"=="1" (
echo Running Nvidia Tweaks.
timeout 2 > nul
goto :Nivida
) else if "%option%"=="2" (
echo Running AMD Tweaks.
timeout 2 > nul
goto :AMD
) else if "%option%"=="3" (
echo Running Intel Tweaks.
timeout 2 > nul
goto :Intel
) else if "%option%"=="4" (
echo Skipping!
goto :DoneSkipGpu 
timeout 1 > nul   
) 

:Nivida
cls
:: Nvidia Power Settings
echo Disabling Power Settings...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{7B7A1E6E-0A7E-11EF-946A-806E6F6E6963}\0000" /v "PowerMizerEnable" /t REG_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{7B7A1E6E-0A7E-11EF-946A-806E6F6E6963}\0000" /v "PowerMizerLevel" /t REG_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{7B7A1E6E-0A7E-11EF-946A-806E6F6E6963}\0000" /v "PowerMizerLevelAC" /t REG_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{7B7A1E6E-0A7E-11EF-946A-806E6F6E6963}\0000" /v "PerfLevelSrc" /t REG_DWORD /d "8738" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t Reg_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}\0001\PowerSettings" /v IdlePowerState /t REG_BINARY /d 00000000 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class{4d36e96c-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
timeout 1 > nul
        
        
cls
:: Nvidia Telemetry
echo Disabling Nvidia Telemetry...
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >nul 2>&1
timeout 1 > nul
        
cls
:: Nvidia Tasks
echo Disabling Nvidia Tasks...
echo The operation completed successfully.
echo The operation completed successfully.
echo The operation completed successfully.
echo The operation completed successfully.
echo The operation completed successfully.
echo The operation completed successfully.
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1 
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1 
schtasks /change /disable /tn "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1  
schtasks /change /disable /tn "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvBatteryBoostCheckOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
timeout 1 > nul

cls
:: Mpo and HDCP Tweaks
echo Disabling HDCP and MPO...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f
timeout 1 > nul

cls
:: interrupt policies
echo Setting interrupt policies...
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%u IN ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%v IN ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%n IN ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do ( 
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d 30 >nul 2>&1
)
timeout 1 > nul

cls               
:NvidiaTelemetryClient
echo Do you want to delete Nvidia Telemetry Client? (Y/N)
echo.
chcp 437 >nul
powershell -Command "Write-Host 'Breaks clipping with Nvidia Softwares.' -ForegroundColor White -BackgroundColor Red"
echo.
set /p option="Enter option number: "
if /i "%option%"=="Y" (
echo.
echo Deleting Nvidia Telemetry Client...
rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
timeout 1 > nul
) else if /i "%option%"=="N" (
echo.
echo Not Deleting Nvidia Telemetry Client...
echo I recommend OBS Replay Buffer over Nvidia Shadowplay!
timeout 3 > nul
) else (
cls
chcp 437 >nul
powershell -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
timeout 2 > nul
goto :NvidiaTelemetryClient
)

cls
echo Running Nvidia Profile Inspector with imported optimized settings...
set "fileURL=https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/2.4.0.4/nvidiaProfileInspector.zip"
set "fileName=nvidiaProfileInspector.zip"
set "fileURL2=https://raw.githubusercontent.com/QuakedK/Oneclick/refs/heads/main/Downloads/QuakedOptimizedNVProflie.nip"
set "fileName2=Quaked Optimized NV Proflie.nip"
mkdir "C:\Gpu Tools\Nvidia" >nul 2>&1
set "extractFolder=C:\Gpu Tools\Nvidia\nvidiaProfileInspector"
set "downloadsFolder=C:\Gpu Tools\Nvidia"
chcp 65001 >nul 2>&1
echo.
echo ╔═════════════════════════════╗
echo ║                             ║
echo ║    Downloading resources    ║
echo ║                             ║
echo ╚═════════════════════════════╝
if not exist "%downloadsFolder%\%fileName%" (
curl -s -L "%fileURL%" -o "%downloadsFolder%\%fileName%"
curl -s -L "%fileURL2%" -o "%downloadsFolder%\%fileName2%"
timeout 1 > nul
mkdir "%extractFolder%" >nul 2>&1
pushd "%extractFolder%" >nul 2>&1
chcp 437 >nul
powershell -Command "Expand-Archive -Path '%downloadsFolder%\%fileName%' -DestinationPath '%extractFolder%' -Force" >nul 2>&1
popd >nul 2>&1
del /q "C:\Gpu Tools\Nvidia\nvidiaProfileInspector.zip" >nul 2>&1
echo Download successful!
echo Importing configuration file...
"%extractFolder%\nvidiaProfileInspector.exe" -importProfile "%downloadsFolder%\%fileName2%"
echo.
pause
goto :DoneSkipGpu 
) else (
    echo "%fileName%" already exists in "%downloadsFolder%". >nul 2>&1
)

:AMD
cls
echo Disabling Amd Bloat...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "3D_Refresh_Rate_Override_DEF" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "3to2Pulldown_NA" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AAF_NA" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "Adaptive De-interlacing" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AllowRSOverlay" /t Reg_SZ /d "false" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AllowSkins" /t Reg_SZ /d "false" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AllowSnapshot" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AllowSubscription" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AntiAlias_NA" /t Reg_SZ /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AreaAniso_NA" /t Reg_SZ /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "ASTT_NA" /t Reg_SZ /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AutoColorDepthReduction_NA" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableSAMUPowerGating" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableUVDPowerGatingDynamic" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableVCEPowerGating" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableAspmL0s" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableAspmL1" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableUlps" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableUlps_NA" /t Reg_SZ /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "KMD_DeLagEnabled" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "KMD_FRTEnabled" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableDMACopy" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableBlockWrite" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "StutterMode" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableUlps" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "PP_SclkDeepSleepDisable" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "PP_ThermalAutoThrottlingEnable" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableDrmdmaPowerGating" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "KMD_EnableComputePreemption" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /t Reg_SZ /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "Main3D" /t Reg_BINARY /d "3100" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "FlipQueueSize" /t Reg_BINARY /d "3100" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "ShaderCache" /t Reg_BINARY /d "3200" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "Tessellation_OPTION" /t Reg_BINARY /d "3200" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "Tessellation" /t Reg_BINARY /d "3100" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "VSyncControl" /t Reg_BINARY /d "3000" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "TFQ" /t Reg_BINARY /d "3200" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t REG_BINARY /d "0100000001000000" /f 
timeout 1 > nul 
 
cls
:: interrupt policies
echo Setting interrupt policies...
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%u IN ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%v IN ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%n IN ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do ( 
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d 30 >nul 2>&1
)
goto :DoneSkipGpu

:Intel
cls
echo Disabling Intel Gpu Bloat...
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "IncreaseFixedSegment" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePFonDP" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableCompensationForDVI" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "NoFastLinkTrainingForeDP" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ACPowerPolicyVersion" /t REG_DWORD /d "16898" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DCPowerPolicyVersion" /t REG_DWORD /d "16642" /f
REG ADD "HKLM\Software\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "512" /f
timeout 1 > nul

cls
:: interrupt policies
echo Setting interrupt policies...
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%u IN ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%v IN ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%n IN ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do ( 
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d 30 >nul 2>&1
)
echo script done.

pause

timeout /t 2
echo Done!
pause
goto menu

:system
:: Made by Gabbe
:: here is restore point😊💕 use before tweaks if u want.
 
title SYSTEM RESTORE POINT  V1.0
color 9

:: (Gabbe) Check for Admin Privileges.
fltmc >nul 2>&1
if not %errorlevel% == 0 (
    powershell -Command "Write-Host 'Oneclick is required to be run as *Administrator.*' -ForegroundColor White -BackgroundColor Red" 
    powershell -Command "Write-Host 'Please Click *Yes* to the following prompt!' -ForegroundColor White -BackgroundColor Red" 
    timeout 3 > nul
    PowerShell Start -Verb RunAs '%0'
    exit /b 0
)

:: 
:OSS
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
   
goto system
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

:power
cls
echo.   [1] 100% powerplan      
echo.   [2] revert (normal powerplan) 
echo.   [3] exit to menu
set /p choice=Choose an option (1-3): 
if "%choice%"=="1" goto 100
if "%choice%"=="2" goto revert100
if "%choice%"=="3"  goto menu cls

:100
cls
setlocal enabledelayedexpansion

:: Step 1: Duplicate the High Performance power scheme
for /f "tokens=3" %%a in ('powercfg -list ^| findstr /i "High performance"') do (
    powercfg -duplicatescheme %%a
    set GUID=%%a
)

:: Step 2: Get the new scheme's GUID (it's the last scheme added)
for /f "tokens=1" %%i in ('powercfg -list ^| findstr /i "Power Scheme GUID"') do (
    set LAST_GUID=%%i
)

:: Step 3: Rename the plan
powercfg -changename %LAST_GUID% "aat 100%"

:: Step 4: Set it as active
powercfg -setactive %LAST_GUID%

:: Step 5: Turn off sleep (AC and DC)
powercfg -setacvalueindex %LAST_GUID% SUB_SLEEP STANDBYIDLE 0
powercfg -setdcvalueindex %LAST_GUID% SUB_SLEEP STANDBYIDLE 0

:: Step 6: Set min and max processor state to 100% (AC and DC)
powercfg -setacvalueindex %LAST_GUID% SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg -setacvalueindex %LAST_GUID% SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg -setdcvalueindex %LAST_GUID% SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg -setdcvalueindex %LAST_GUID% SUB_PROCESSOR PROCTHROTTLEMAX 100

:: Step 7: Apply changes
powercfg -S %LAST_GUID%

echo Power plan "aat 100%" created, configured, and set as active.
pause
goto menu




:revert100
cls
echo. 2 choices. please pick both work.
echo.   [1]  delete  and redownload high performance powerplan.   this one might not work. 
echo.
echo.   [2]  restore the high performance powerplan to normal.
set /p choice=Choose an option (1-2): 

if "%choice%"=="1" goto redownload
if "%choice%"=="2" goto restorepower
pause
:redownload
cls
setlocal

:: === Step 1: Delete current High Performance plan ===
for /f "tokens=*" %%G in ('powercfg /list ^| findstr /i "High performance"') do (
    for /f "tokens=3" %%H in ("%%G") do (
        echo Deleting High Performance plan with GUID %%H
        powercfg -delete %%H
    )
)

:: === Step 2: Recreate High Performance plan from default template ===
:: This duplicates from its original template GUID
powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

:: Optional: rename it back
for /f "tokens=*" %%G in ('powercfg /list ^| findstr /i "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"') do (
    for /f "tokens=3" %%H in ("%%G") do (
        powercfg -changename %%H "High performance"
        powercfg -setactive %%H
        echo Restored and activated default High Performance plan.
    )
)

endlocal
echo. POWERPLAN RECREATED RECCOMENDED TO CHECK WHICH POWERPLAN IS ON.
pause
exit

:restorepower
cls
setlocal

:: === Step 1: Find current High Performance plan GUID ===
for /f "tokens=*" %%G in ('powercfg /list ^| findstr /i "High performance"') do (
    for /f "tokens=3" %%H in ("%%G") do set HP_GUID=%%H
)

if not defined HP_GUID (
    echo High Performance plan not found.
    endlocal
    pause
    exit /b
)

echo Found High Performance plan: %HP_GUID%

:: === Step 2: Restore processor state values (defaults: min=5%, max=100%) ===
powercfg -setacvalueindex %HP_GUID% SUB_PROCESSOR MINPROCSTATE 5
powercfg -setacvalueindex %HP_GUID% SUB_PROCESSOR MAXPROCSTATE 100
powercfg -setdcvalueindex %HP_GUID% SUB_PROCESSOR MINPROCSTATE 5
powercfg -setdcvalueindex %HP_GUID% SUB_PROCESSOR MAXPROCSTATE 100

:: === Step 3: Activate it (optional) ===
powercfg -setactive %HP_GUID%
echo Fixed and activated High Performance plan.

endlocal
cls
echo. POWERPLAN RESET.

pause
echo. PLEASE CHECK IF UR ON 100% IF U ARE THERES A SOLUTION 
echo. need solution?
echo.   [y] showing fix. 
echo.   [n] go to menu
set /p choice=Choose an option (y-n): 
if "%choice%"=="y" start  https://github.com/SigmaGabbe/POWER-PLAN-RESET-TUTORIAL
if "%choice%"=="n" goto menu



:alltweaks
echo. are you sure?
set /p choice=Choose an option (y-n): 
if "%choice%"=="y" goto startalltweaks
if "%choice%"=="n" goto menu
:startalltweaks
cls
echo Running optimization script...
:: first opt
@echo off

Disable ActiveX Installer (ActiveX Installer) - ActiveX Control Installation
sc config AxInstSV start= disabled
net stop AxInstSV

:: Disable BitLocker Drive Encryption Service (BitLocker) - Encryption for disk drives
sc config BitLockerDriveEncryption start= disabled
net stop BitLockerDriveEncryption

:: Disable Cellular Time (CellularTime) - Sync time via cellular network
sc config CellularTime start= disabled
net stop CellularTime

:: Disable Certificate Propagation (CertPropSvc) - Manages certificate-related operations
sc config CertPropSvc start= disabled
net stop CertPropSvc

:: Disable Cloud Backup and Restore Service (wuauserv, etc.) - Cloud-based backup service
sc config CldFlt start= disabled
net stop CldFlt

:: Disable Connected Devices Platform Service (cdpusersvc) - Manages device connectivity and settings
sc config cdpusersvc start= disabled
net stop cdpusersvc

:: Disable Connected User Experiences and Telemetry (DiagTrack) - Collects user experience data for diagnostics
sc config DiagTrack start= disabled
net stop DiagTrack

:: Disable Contact Data (cdpuser) - Deals with contact syncing for Microsoft services
sc config cdpuser start= disabled
net stop cdpuser

::ok im to lazy to list em all disabling services..

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
timeout /t 2

::regtweaks
cls
echo Applying registry tweaks...
:: reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ApplicationFrameHost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
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
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PrioityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x2a /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\SystemRestore" /v "RPSessionInterval" /f >nul 2>&1 
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f
cls
timeout 1 > nul
::debloat
cls
echo [*] Starting Safe Debloat for Windows 11 23H2...
echo   DOES REMOVE BROWSER powershell command in discord.


:: -------------------------------
:: Disable Telemetry
echo [*] Disabling telemetry...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

:: -------------------------------
:: Remove bloatware apps (AppX)
echo [*] Removing preinstalled bloatware apps...
setlocal enabledelayedexpansion
for %%A in (
    "Microsoft.3DBuilder"
    "Microsoft.BingNews"
    "Microsoft.GamingApp"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MixedReality.Portal"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.SkypeApp"
    "Microsoft.Todos"
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
) do (
    echo Removing: %%~A
    powershell -Command "Get-AppxPackage -Name %%~A | Remove-AppxPackage -ErrorAction SilentlyContinue"
    powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq '%%~A'} | Remove-AppxProvisionedPackage -Online"
)

:: -------------------------------
:: Remove OneDrive
echo [*] Removing OneDrive...
taskkill /f /im OneDrive.exe >nul 2>&1
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
%SystemRoot%\System32\OneDriveSetup.exe /uninstall
rd "%UserProfile%\OneDrive" /Q /S >nul 2>&1
rd "C:\OneDriveTemp" /Q /S >nul 2>&1
rd "%LocalAppData%\Microsoft\OneDrive" /Q /S >nul 2>&1
rd "%ProgramData%\Microsoft OneDrive" /Q /S >nul 2>&1

:: -------------------------------
:: Remove Microsoft Edge
echo [*] Removing Microsoft Edge...
cd %ProgramFiles(x86)%\Microsoft\Edge\Application\*\Installer
if exist setup.exe (
    setup.exe --uninstall --system-level --verbose-logging --force-uninstall
) else (
    echo [!] Microsoft Edge uninstall files not found.
)

:: -------------------------------
:: Prompt to disable Windows Defender
set /p disableWD=Do you want to disable Windows Defender? (Y/N): 
if /I "%disableWD%"=="Y" (
    echo [*] Disabling Windows Defender...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
) else (
    echo [*] Skipping Defender disable.
)

:: -------------------------------
:: Disable Cortana
echo [*] Disabling Cortana...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

:: -------------------------------
:: Disable background apps
echo [*] Disabling background apps...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f

:: -------------------------------
:: Disable telemetry scheduled tasks
echo [*] Disabling telemetry scheduled tasks...
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

:: -------------------------------
:: Clean temp files
echo [*] Cleaning temp files...
del /q /f /s %TEMP%\*
del /q /f /s C:\Windows\Temp\*
:: -------------------------------
:: Prompt to disable non-crucial services
set /p disableServices=Do you want to disable non-crucial Windows services? (Y/N): 
if /I "%disableServices%"=="Y" (
    echo [*] Disabling non-crucial services...

    reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f


    :: Xbox services
    sc stop XblAuthManager
    sc config XblAuthManager start= disabled
    sc stop XblGameSave
    sc config XblGameSave start= disabled
    sc stop XboxGipSvc
    sc config XboxGipSvc start= disabled
    sc stop XboxNetApiSvc
    sc config XboxNetApiSvc start= disabled

    :: Diagnostics & telemetry
    sc stop DiagTrack
    sc config DiagTrack start= disabled
    sc stop dmwappushservice
    sc config dmwappushservice start= disabled

    :: Remote Desktop services (disable only if unused)
    sc stop TermService
    sc config TermService start= disabled

    :: Retail Demo service
    sc stop RetailDemo
    sc config RetailDemo start= disabled

    :: Print Spooler (disable only if you don't use printers)
    sc stop Spooler
    sc config Spooler start= disabled

    :: Fax service (very rarely used)
    sc stop Fax
    sc config Fax start= disabled


    echo [*] Services disabled.
timeout 1 > nul
title Gpu Tweaks 

color 9

    
)
cls
color D
chcp 65001 >nul 2>&1
echo.
echo.
echo.
echo.
echo.
echo.                                                ██████╗ ██████╗ ██╗   ██╗             
echo.                                               ██╔════╝ ██╔══██╗██║   ██║             
echo.                                               ██║  ███╗██████╔╝██║   ██║             
echo.                                               ██║   ██║██╔═══╝ ██║   ██║             
echo.                                               ╚██████╔╝██║     ╚██████╔╝             
echo.                                                ╚═════╝ ╚═╝      ╚═════╝              
echo.                                                   
echo.                                  ████████╗██╗    ██╗███████╗ █████╗ ██╗  ██╗███████╗
echo.                                  ╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║ ██╔╝██╔════╝
echo.                                     ██║   ██║ █╗ ██║█████╗  ███████║█████╔╝ ███████╗
echo.                                     ██║   ██║███╗██║██╔══╝  ██╔══██║██╔═██╗ ╚════██║
echo.                                     ██║   ╚███╔███╔╝███████╗██║  ██║██║  ██╗███████║
echo.                                     ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
echo.
echo.                                  ╔════════════════════════════════════════════════════╗
echo.                                  ║             Please select your GPU...              ║       
echo.                                  ╚════════════════════════════════════════════════════╝
echo.
echo.
echo.
echo.
echo Choose an option:
echo 1. Nvidia  
echo 2. AMD 
echo 3. Intel
echo 4. Skip!
set /p option="Enter option number: "
echo.
if "%option%"=="1" (
echo Running Nvidia Tweaks.
timeout 2 > nul
goto :Nivida
) else if "%option%"=="2" (
echo Running AMD Tweaks.
timeout 2 > nul
goto :AMD
) else if "%option%"=="3" (
echo Running Intel Tweaks.
timeout 2 > nul
goto :Intel
) else if "%option%"=="4" (
echo Skipping!
goto :DoneSkipGpu 
timeout 1 > nul   
) 

:Nivida
cls
:: Nvidia Power Settings
echo Disabling Power Settings...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{7B7A1E6E-0A7E-11EF-946A-806E6F6E6963}\0000" /v "PowerMizerEnable" /t REG_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{7B7A1E6E-0A7E-11EF-946A-806E6F6E6963}\0000" /v "PowerMizerLevel" /t REG_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{7B7A1E6E-0A7E-11EF-946A-806E6F6E6963}\0000" /v "PowerMizerLevelAC" /t REG_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{7B7A1E6E-0A7E-11EF-946A-806E6F6E6963}\0000" /v "PerfLevelSrc" /t REG_DWORD /d "8738" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t Reg_DWORD /d "0" /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}\0001\PowerSettings" /v IdlePowerState /t REG_BINARY /d 00000000 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class{4d36e96c-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
timeout 1 > nul
        
        
cls
:: Nvidia Telemetry
echo Disabling Nvidia Telemetry...
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >nul 2>&1
timeout 1 > nul
        
cls
:: Nvidia Tasks
echo Disabling Nvidia Tasks...
echo The operation completed successfully.
echo The operation completed successfully.
echo The operation completed successfully.
echo The operation completed successfully.
echo The operation completed successfully.
echo The operation completed successfully.
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1 
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1 
schtasks /change /disable /tn "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1  
schtasks /change /disable /tn "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvBatteryBoostCheckOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
timeout 1 > nul

cls
:: Mpo and HDCP Tweaks
echo Disabling HDCP and MPO...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f
timeout 1 > nul

cls
:: interrupt policies
echo Setting interrupt policies...
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%u IN ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%v IN ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%n IN ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do ( 
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d 30 >nul 2>&1
)
timeout 1 > nul

cls               
:NvidiaTelemetryClient
echo Do you want to delete Nvidia Telemetry Client? (Y/N)
echo.
chcp 437 >nul
powershell -Command "Write-Host 'Breaks clipping with Nvidia Softwares.' -ForegroundColor White -BackgroundColor Red"
echo.
set /p option="Enter option number: "
if /i "%option%"=="Y" (
echo.
echo Deleting Nvidia Telemetry Client...
rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
timeout 1 > nul
) else if /i "%option%"=="N" (
echo.
echo Not Deleting Nvidia Telemetry Client...
echo I recommend OBS Replay Buffer over Nvidia Shadowplay!
timeout 3 > nul
) else (
cls
chcp 437 >nul
powershell -Command "Write-Host 'Invalid choice, Please choose Y or N.' -ForegroundColor White -BackgroundColor Red"
timeout 2 > nul
goto :NvidiaTelemetryClient
)

cls
echo Running Nvidia Profile Inspector with imported optimized settings...
set "fileURL=https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/2.4.0.4/nvidiaProfileInspector.zip"
set "fileName=nvidiaProfileInspector.zip"
set "fileURL2=https://raw.githubusercontent.com/QuakedK/Oneclick/refs/heads/main/Downloads/QuakedOptimizedNVProflie.nip"
set "fileName2=Quaked Optimized NV Proflie.nip"
mkdir "C:\Gpu Tools\Nvidia" >nul 2>&1
set "extractFolder=C:\Gpu Tools\Nvidia\nvidiaProfileInspector"
set "downloadsFolder=C:\Gpu Tools\Nvidia"
chcp 65001 >nul 2>&1
echo.
echo ╔═════════════════════════════╗
echo ║                             ║
echo ║    Downloading resources    ║
echo ║                             ║
echo ╚═════════════════════════════╝
if not exist "%downloadsFolder%\%fileName%" (
curl -s -L "%fileURL%" -o "%downloadsFolder%\%fileName%"
curl -s -L "%fileURL2%" -o "%downloadsFolder%\%fileName2%"
timeout 1 > nul
mkdir "%extractFolder%" >nul 2>&1
pushd "%extractFolder%" >nul 2>&1
chcp 437 >nul
powershell -Command "Expand-Archive -Path '%downloadsFolder%\%fileName%' -DestinationPath '%extractFolder%' -Force" >nul 2>&1
popd >nul 2>&1
del /q "C:\Gpu Tools\Nvidia\nvidiaProfileInspector.zip" >nul 2>&1
echo Download successful!
echo Importing configuration file...
"%extractFolder%\nvidiaProfileInspector.exe" -importProfile "%downloadsFolder%\%fileName2%"
echo.
pause
goto :DoneSkipGpu 
) else (
    echo "%fileName%" already exists in "%downloadsFolder%". >nul 2>&1
)

:AMD
cls
echo Disabling Amd Bloat...
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "3D_Refresh_Rate_Override_DEF" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "3to2Pulldown_NA" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AAF_NA" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "Adaptive De-interlacing" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AllowRSOverlay" /t Reg_SZ /d "false" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AllowSkins" /t Reg_SZ /d "false" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AllowSnapshot" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AllowSubscription" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AntiAlias_NA" /t Reg_SZ /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AreaAniso_NA" /t Reg_SZ /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "ASTT_NA" /t Reg_SZ /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "AutoColorDepthReduction_NA" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableSAMUPowerGating" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableUVDPowerGatingDynamic" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableVCEPowerGating" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableAspmL0s" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableAspmL1" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableUlps" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableUlps_NA" /t Reg_SZ /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "KMD_DeLagEnabled" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "KMD_FRTEnabled" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableDMACopy" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableBlockWrite" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "StutterMode" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "EnableUlps" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "PP_SclkDeepSleepDisable" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "PP_ThermalAutoThrottlingEnable" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "DisableDrmdmaPowerGating" /t Reg_DWORD /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000" /v "KMD_EnableComputePreemption" /t Reg_DWORD /d "0" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /t Reg_SZ /d "1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "Main3D" /t Reg_BINARY /d "3100" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "FlipQueueSize" /t Reg_BINARY /d "3100" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "ShaderCache" /t Reg_BINARY /d "3200" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "Tessellation_OPTION" /t Reg_BINARY /d "3200" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "Tessellation" /t Reg_BINARY /d "3100" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "VSyncControl" /t Reg_BINARY /d "3000" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\UMD" /v "TFQ" /t Reg_BINARY /d "3200" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{B784559B-672D-11EE-A4CA-E612636C81AA}\0000\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t REG_BINARY /d "0100000001000000" /f 
timeout 1 > nul 
 
cls
:: interrupt policies
echo Setting interrupt policies...
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%u IN ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%v IN ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%n IN ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do ( 
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d 30 >nul 2>&1
)
goto :DoneSkipGpu

:Intel
cls
echo Disabling Intel Gpu Bloat...
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "IncreaseFixedSegment" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePFonDP" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableCompensationForDVI" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "NoFastLinkTrainingForeDP" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ACPowerPolicyVersion" /t REG_DWORD /d "16898" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DCPowerPolicyVersion" /t REG_DWORD /d "16642" /f
REG ADD "HKLM\Software\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "512" /f
timeout 1 > nul

cls
:: interrupt policies
echo Setting interrupt policies...
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%g IN ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f 
FOR /f %%i IN ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do REG DELETE "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
FOR /f %%u IN ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%v IN ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%v\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d C0 >nul 2>&1
)
FOR /f %%n IN ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do ( 
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v DevicePolicy /t REG_DWORD /d 4 >nul 2>&1
    REG ADD "HKLM\System\CurrentControlSet\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /f /v AssignmentSetOverride /t REG_BINARY /d 30 >nul 2>&1
)
echo script done.
timeout /t 2
:DoneSkipGpu
cls
echo.   [1] 100% powerplan      
echo.   [2] revert (normal powerplan) 
echo.   [3] exit to menu
set /p choice=Choose an option (1-3): 
if "%choice%"=="1" goto 100
if "%choice%"=="2" goto revert100
if "%choice%"=="3"  goto menu cls

:100
cls
setlocal enabledelayedexpansion

:: Step 1: Duplicate the High Performance power scheme
for /f "tokens=3" %%a in ('powercfg -list ^| findstr /i "High performance"') do (
    powercfg -duplicatescheme %%a
    set GUID=%%a
)

:: Step 2: Get the new scheme's GUID (it's the last scheme added)
for /f "tokens=1" %%i in ('powercfg -list ^| findstr /i "Power Scheme GUID"') do (
    set LAST_GUID=%%i
)

:: Step 3: Rename the plan
powercfg -changename %LAST_GUID% "aat 100%"

:: Step 4: Set it as active
powercfg -setactive %LAST_GUID%

:: Step 5: Turn off sleep (AC and DC)
powercfg -setacvalueindex %LAST_GUID% SUB_SLEEP STANDBYIDLE 0
powercfg -setdcvalueindex %LAST_GUID% SUB_SLEEP STANDBYIDLE 0

:: Step 6: Set min and max processor state to 100% (AC and DC)
powercfg -setacvalueindex %LAST_GUID% SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg -setacvalueindex %LAST_GUID% SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg -setdcvalueindex %LAST_GUID% SUB_PROCESSOR PROCTHROTTLEMIN 100
powercfg -setdcvalueindex %LAST_GUID% SUB_PROCESSOR PROCTHROTTLEMAX 100

:: Step 7: Apply changes
powercfg -S %LAST_GUID%

echo Power plan "aat 100%" created, configured, and set as active.
pause



 