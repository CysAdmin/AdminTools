<#
.SYNOPSIS
    Encrypt's and Decrypt's a String based on a Password

.DESCRIPTION
    Encrypt's and Decrypt's a String based on a SecureString Password. Encryption is done with 10000 Iterations (Default)

.PARAMETER Encrypt
    Switch to declare the Ecryption Status

.PARAMETER Decrypt
    Switch to declare the Decryption Status

.PARAMETER EncryptedString
    The Encrypted String in Base64 Format.
.PARAMETER PlainText
    The Decrypted String.

.PARAMETER Password
    The Password for Encryption / Decryption. MUST be a SecureString Object

.PARAMETER Salt
    Set a Custom Salt Value

.PARAMETER Iterations
    Set a Custom Iteration Value [int32]. Default is set to 10.000 Iterations. Encryption & Decryption Iterations must be the same

.EXAMPLE
    .\Encrypt-Decrypt.ps1 -Password (Read-Host -AsSecureString) -Encrypt -PlainText "This Text will be encrypted"
    Example Output: jB/tenW7QNpQFXMhx6HasQ==

.EXAMPLE
    .\Encrypt-Decrypt.ps1 -Password (Read-Host -AsSecureString) -Iterations 20000 -Encrypt -PlainText "This Text will be encrypted with 20000 Iterations"
    Example Output: sP8oBDYOJ1HDfcBMcCiYqN+cPRpycgwPKs0JPyBkSnXew13XOvjeJiwC9hfoUVjx+//C9Nyo2bTrVPIL+oyO6g==

.EXAMPLE
    .\Encrypt-Decrypt.ps1 -Password (Read-Host -AsSecureString) -Iterations 20000 -Decrypt 
    ´ -EncryptedString sP8oBDYOJ1HDfcBMcCiYqN+cPRpycgwPKs0JPyBkSnXew13XOvjeJiwC9hfoUVjx+//C9Nyo2bTrVPIL+oyO6g==
    Example Output: This Text will be encrypted with 20000 Iterations

.NOTES
    Author: Tim 
    Date: 20.04.2024
    Version: 1.0
#>

[CmdletBinding(DefaultParameterSetName = 'Ecnrypted')]
param (
        [Parameter(Mandatory,ParameterSetName = 'Encrypt')]
        [switch] $Encrypt,
        
        [Parameter(Mandatory,ParameterSetName = 'Decrypt')]
        [switch] $Decrypt,

        [Parameter(Mandatory, ParameterSetName = 'Decrypt')]
        [ValidateNotNullOrEmpty()]
        [string]$EncryptedString,

        [Parameter(Mandatory, ParameterSetName = "Encrypt")]
        [ValidateNotNullOrEmpty()]
        [String]$PlainText,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [securestring] $Password,

        [ValidateNotNullOrEmpty()]
        [string]$Salt = "NC2jhdiMm26omW6Z7NsblQ==",

        [ValidateNotNullOrEmpty()]
        [int32]$Iterations = 10000
) 

function ConvertTo-SecureByteArray{
    param(
        [SecureString]$Password
    )

    # Convert SecureString password to byte array
    $Ptr = [System.Security.SecureStringMarshal]::SecureStringToGlobalAllocUnicode($Password)
    $CharArray = @()
    $PasswordByteArray = @()
    try {
        # Convert SecureString to string, split into characters, and convert each character to byte array
        $CharArray = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr) -split ""
        foreach ($Char in $CharArray) {
            $PasswordByteArray += [System.Text.Encoding]::Unicode.GetBytes($Char)
        }
        $PasswordByteArray
    }
    finally {
        # Free memory allocated for SecureString
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
    }
}

function Get-EncryptedString{
    param(
        [String]$PlainText,
        [byte[]] $Key,
        [byte[]] $Iv
    )

    $PlainTextBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)

    try {
        $encryptor = $aesAlg.CreateEncryptor($Key, $Iv)

        # Encrypt the plaintext
        $msEncrypt = New-Object System.IO.MemoryStream
        $csEncrypt = New-Object System.Security.Cryptography.CryptoStream($msEncrypt, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        # Write the bytes to the crypto stream
        $csEncrypt.Write($PlainTextBytes, 0, $PlainTextBytes.Length)
        $csEncrypt.FlushFinalBlock() # Flush final block to ensure all data is written
        $csEncrypt.Close()

        # Get the encrypted bytes
        $encryptedBytes = $msEncrypt.ToArray()

        # Convert encrypted bytes to base64 string (for easy representation)
        $encryptedBase64 = [Convert]::ToBase64String($encryptedBytes)

        $encryptedBase64    
    }
    catch {
        write-output "Something went wrong!"
        Write-Output $_.ErrorDetails.Message
    }

}

function Get-DecryptedString{
    param(
        [String]$EncryptedString,
        [byte[]] $Key,
        [byte[]] $Iv
    )
    $decryptor = $aesAlg.CreateDecryptor($key, $iv)
    
    try {
        $encryptedBytes = [Convert]::FromBase64String($EncryptedString)
    }
    catch {
        write-output "Incorrect Input!"
        exit 0
    }

    try {
        # Decrypt the bytes
        $msDecrypt = New-Object System.IO.MemoryStream
        $msDecrypt.Write($encryptedBytes, 0, $encryptedBytes.Length)
        $msDecrypt.Position = 0
        $csDecrypt = New-Object System.Security.Cryptography.CryptoStream($msDecrypt, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        $srDecrypt = New-Object System.IO.StreamReader($csDecrypt)
        $decryptedText = $srDecrypt.ReadToEnd()
        $decryptedText        
    }
    catch {
        # Handle incorrect password
        write-output "Wrong Password!"
        exit 0
    }
}

$PasswordByteArray = ConvertTo-SecureByteArray -Password $Password

# Convert salt to byte array
[byte[]] $SaltBytes = [System.Text.Encoding]::UTF8.GetBytes($Salt)

# Derive key and IV using PBKDF2 with the provided password and salt
[byte[]] $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordByteArray, $SaltBytes, $Iterations).GetBytes(32)
[byte[]] $iv = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordByteArray, $SaltBytes, $Iterations).GetBytes(16)

# Create AES encryption algorithm object
$aesAlg = [System.Security.Cryptography.AesManaged]::Create("aes")


if($Encrypt){
    Get-EncryptedString -PlainText $PlainText -Key $key -Iv $iv
}elseif($Decrypt){
    Get-DecryptedString -EncryptedString $EncryptedString -Key $key -Iv $iv
}
