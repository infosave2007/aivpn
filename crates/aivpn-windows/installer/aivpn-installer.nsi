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
!include "${STAGE_DIR}/routing-bootstrap.nsh"
!define APP_NAME "AIVPN"
!define START_MENU_DIR "$SMPROGRAMS\AIVPN"
!define UNINSTALL_REG_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AIVPN"
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
  StrCpy $INSTDIR "$PROGRAMFILES64\AIVPN"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "${STAGE_DIR}/aivpn.exe"
  ClearErrors
  ExecWait '"$PLUGINSDIR\aivpn.exe" setup install' $0
  IfErrors install_failed
  StrCmp $0 0 basic_done
  StrCmp $0 10 install_reboot
  Goto install_failed
basic_done:
!if ${ROUTING_ENABLED} == 1
  ExecWait '"$PLUGINSDIR\aivpn.exe" app-routing install' $0
  IfErrors install_failed
  StrCmp $0 0 install_done
  StrCmp $0 10 install_reboot
  Goto install_failed
!else
  Goto install_done
!endif
install_reboot:
  SetRebootFlag true
  Goto install_done
install_failed:
  DetailPrint "Установка не завершена. Прежние файлы и журнал восстановления сохранены."
  SetErrorLevel 1
  Abort
install_done:
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\uninstall-aivpn.exe"
  CreateDirectory "${START_MENU_DIR}"
  CreateShortcut "${START_MENU_DIR}\AIVPN.lnk" "$INSTDIR\aivpn.exe" "" "$INSTDIR\aivpn.exe"
  CreateShortcut "${START_MENU_DIR}\Uninstall AIVPN.lnk" "$INSTDIR\uninstall-aivpn.exe"
  CreateShortcut "$DESKTOP\AIVPN.lnk" "$INSTDIR\aivpn.exe" "" "$INSTDIR\aivpn.exe"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "Publisher" "AIVPN"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_REG_KEY}" "UninstallString" '$\"$INSTDIR\uninstall-aivpn.exe$\"'
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_REG_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  CopyFiles /SILENT "$INSTDIR\aivpn.exe" "$PLUGINSDIR\aivpn.exe"
  IfErrors uninstall_failed
  IfFileExists "$PROGRAMFILES64\AIVPNRouting\installation.json" 0 routing_removed
  ExecWait '"$PLUGINSDIR\aivpn.exe" app-routing uninstall' $0
  IfErrors uninstall_failed
  StrCmp $0 10 uninstall_reboot
  StrCmp $0 0 routing_removed
  Goto uninstall_failed
routing_removed:
  ExecWait '"$PLUGINSDIR\aivpn.exe" setup uninstall' $0
  IfErrors uninstall_failed
  StrCmp $0 0 uninstall_done
  Goto uninstall_failed
uninstall_reboot:
  SetRebootFlag true
  DetailPrint "Для завершения удаления нужна перезагрузка и повторный запуск удаления."
  SetErrorLevel 3010
  Abort
uninstall_failed:
  DetailPrint "Удаление не подтверждено. Файлы и защита сохранены для повторной попытки."
  SetErrorLevel 1
  Abort
uninstall_done:
  Delete "$DESKTOP\AIVPN.lnk"
  Delete "${START_MENU_DIR}\AIVPN.lnk"
  Delete "${START_MENU_DIR}\Uninstall AIVPN.lnk"
  RMDir "${START_MENU_DIR}"
  Delete "$INSTDIR\image-installation.lock"
  Delete "$INSTDIR\uninstall-aivpn.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_REG_KEY}"
SectionEnd
