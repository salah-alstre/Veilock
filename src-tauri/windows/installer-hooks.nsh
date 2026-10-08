; Veilock NSIS installer hooks.
; Per-user (HKCU) registration only: no admin rights, nothing outside the user's hive, and the
; uninstaller removes exactly what the installer added. User-encrypted .veil files are never touched.
;
; Explorer context-menu entries are OPTIONAL and are created by the app itself from
; Settings > Windows Integration (so the user can toggle them without reinstalling).
; The installer only cleans them up on uninstall.

!macro NSIS_HOOK_PREINSTALL
!macroend

!macro NSIS_HOOK_POSTINSTALL
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Remove context-menu verbs the app may have registered. Safe if absent.
  DeleteRegKey HKCU "Software\Classes\*\shell\Veilock.Encrypt"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\Veilock.Encrypt"
  DeleteRegKey HKCU "Software\Classes\.veil\shell\Veilock.Open"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Veilock"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
!macroend
