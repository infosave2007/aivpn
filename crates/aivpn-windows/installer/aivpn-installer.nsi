Unicode True

!include "MUI2.nsh"

!ifndef APP_VERSION
!error "APP_VERSION is required"
!endif

!ifndef STAGE_DIR
!error "STAGE_DIR is required"
!endif

!ifndef OUTPUT_EXE
!error "OUTPUT_EXE is required"
!endif

!define APP_NAME "AIVPN"
!define COMPANY_NAME "AIVPN"
!define START_MENU_DIR "$SMPROGRAMS\AIVPN"
!define UNINSTALL_REG_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AIVPN"
!define UNINSTALL_EXE "$INSTDIR\uninstall-aivpn.exe"

Name "${APP_NAME}"
OutFile "${OUTPUT_EXE}"
InstallDir "$PROGRAMFILES64\AIVPN"
RequestExecutionLevel admin
BrandingText "AIVPN ${APP_VERSION}"
ShowInstDetails show
ShowUnInstDetails show

!define MUI_ABORTWARNING
!define MUI_ICON "${STAGE_DIR}/aivpn.ico"
!define MUI_UNICON "${STAGE_DIR}/aivpn.ico"

!insertmacro MUI_PAGE_WELCOME
!define MUI_DIRECTORYPAGE_VERIFYONLEAVE
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"

Section "Install" SecInstall
  SetShellVarContext all
  SetRegView 64
  SetOutPath "$INSTDIR"

  Delete "$INSTDIR\uninstall.cmd"
  Delete "$INSTDIR\uninstall-aivpn.cmd"
  Delete "$INSTDIR\uninstall-aivpn.ps1"
  Delete "$INSTDIR\start-client.ps1"
  Delete "$INSTDIR\stop-client.ps1"
  Delete "$INSTDIR\smoke-test.ps1"
  Delete "$INSTDIR\Launch-AIVPN.vbs"
  Delete "$INSTDIR\AivpnTray.ps1"
  Delete "$INSTDIR\README_WINDOWS.md"
  Delete "${START_MENU_DIR}\AIVPN.lnk"
  Delete "${START_MENU_DIR}\Uninstall AIVPN.lnk"
  Delete "$DESKTOP\AIVPN.lnk"

  File "${STAGE_DIR}/aivpn.exe"
  File "${STAGE_DIR}/aivpn-client.exe"
  File "${STAGE_DIR}/wintun.dll"
  File "${STAGE_DIR}/aivpn.ico"

  WriteUninstaller "${UNINSTALL_EXE}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "Publisher" "${COMPANY_NAME}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "UninstallString" "${UNINSTALL_EXE}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayIcon" "$INSTDIR\aivpn.ico"
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "NoRepair" 1

  CreateDirectory "${START_MENU_DIR}"
  CreateShortcut "${START_MENU_DIR}\AIVPN.lnk" "$INSTDIR\aivpn.exe" "" "$INSTDIR\aivpn.ico" 0
  CreateShortcut "${START_MENU_DIR}\Uninstall AIVPN.lnk" "${UNINSTALL_EXE}" "" "${UNINSTALL_EXE}" 0
  CreateShortcut "$DESKTOP\AIVPN.lnk" "$INSTDIR\aivpn.exe" "" "$INSTDIR\aivpn.ico" 0
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64

  ; Clean up kill-switch firewall rules BEFORE deleting the client binary.
  ; If the user uninstalls while kill-switch is active the netsh blockoutbound
  ; policy and allow rules would otherwise survive reboot with no way to remove them.
  ExecWait '"$INSTDIR\aivpn-client.exe" kill-switch clear'
  ; Belt-and-suspenders: remove rules and restore policy directly via netsh
  ; in case the binary above already failed or was deleted manually.
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="AIVPN_KS_ALLOW_VPN"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="AIVPN_KS_ALLOW_SERVER"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="AIVPN_KS_ALLOW_LOCAL"'
  nsExec::ExecToLog 'netsh advfirewall set currentprofile firewallpolicy allowinbound,allowoutbound'

  Delete "$DESKTOP\AIVPN.lnk"
  Delete "${START_MENU_DIR}\AIVPN.lnk"
  Delete "${START_MENU_DIR}\Uninstall AIVPN.lnk"
  RMDir "${START_MENU_DIR}"

  Delete "$INSTDIR\aivpn.exe"
  Delete "$INSTDIR\aivpn-client.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\aivpn.ico"
  Delete "$INSTDIR\uninstall.cmd"
  Delete "$INSTDIR\uninstall-aivpn.cmd"
  Delete "$INSTDIR\uninstall-aivpn.ps1"
  Delete "$INSTDIR\start-client.ps1"
  Delete "$INSTDIR\stop-client.ps1"
  Delete "$INSTDIR\smoke-test.ps1"
  Delete "$INSTDIR\Launch-AIVPN.vbs"
  Delete "$INSTDIR\AivpnTray.ps1"
  Delete "$INSTDIR\README_WINDOWS.md"
  Delete "${UNINSTALL_EXE}"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${UNINSTALL_REG_KEY}"
SectionEnd
