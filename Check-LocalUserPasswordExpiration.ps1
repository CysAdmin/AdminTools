$currentDate = Get-Date
$fullUserName = (Get-CimInstance -Class   Win32_ComputerSystem | Select-Object UserName).UserName
$currentUserName = $fullUserName.split("\")[1]
$currentUser = Get-LocalUser -Name $currentUserName
$passwordExpiration = $currentUser.PasswordExpires   


# FOR PS2EXE WITH CONSOLE OPUTPUT
# Write-Host -NoNewLine 'Press any key to continue...';
#$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');