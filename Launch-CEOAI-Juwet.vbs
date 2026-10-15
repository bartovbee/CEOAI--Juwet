Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
exePath = fso.BuildPath(baseDir, "CEOAI-Juwet.exe")
If fso.FileExists(exePath) Then
  shell.Run """" & exePath & """", 0, False
Else
  MsgBox "CEOAI-Juwet.exe tidak ditemukan di folder aplikasi.", 16, "CEOAI Juwet"
End If
