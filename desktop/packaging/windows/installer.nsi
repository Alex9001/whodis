Unicode true
RequestExecutionLevel user

!ifndef APP_SOURCE
  !error "APP_SOURCE is required"
!endif
!ifndef VERSION
  !define VERSION "dev"
!endif
!ifndef OUTPUT_FILE
  !define OUTPUT_FILE "whodis-gui-setup.exe"
!endif
!ifndef APP_ICON
  !error "APP_ICON is required"
!endif

Name "Whodis"
OutFile "${OUTPUT_FILE}"
Icon "${APP_ICON}"
UninstallIcon "${APP_ICON}"
InstallDir "$LOCALAPPDATA\Programs\Whodis"
InstallDirRegKey HKCU "Software\Whodis" "InstallDir"

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Whodis" SEC_MAIN
  SetOutPath "$INSTDIR"
  File /r "${APP_SOURCE}\*"
  WriteRegStr HKCU "Software\Whodis" "InstallDir" "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\Whodis"
  CreateShortcut "$SMPROGRAMS\Whodis\Whodis.lnk" "$INSTDIR\whodis-gui.exe"
  CreateShortcut "$DESKTOP\Whodis.lnk" "$INSTDIR\whodis-gui.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Whodis" "DisplayName" "Whodis"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Whodis" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Whodis" "Publisher" "Aleksandr Oreshkin"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Whodis" "UninstallString" '"$INSTDIR\Uninstall.exe"'
SectionEnd

Section "Uninstall"
  Delete "$DESKTOP\Whodis.lnk"
  Delete "$SMPROGRAMS\Whodis\Whodis.lnk"
  RMDir "$SMPROGRAMS\Whodis"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Whodis"
  DeleteRegKey HKCU "Software\Whodis"
  RMDir /r "$INSTDIR"
SectionEnd
