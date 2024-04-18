$currentDate = Get-Date
$fullUserName = (Get-CimInstance -Class   Win32_ComputerSystem | Select-Object UserName).UserName
$currentUserName = $fullUserName.split("\")[1]
$currentUser = Get-LocalUser -Name $currentUserName
$passwordExpiration = $currentUser.PasswordExpires   