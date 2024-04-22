<#
.SYNOPSIS
Encrypts or decrypts a file or string using AES encryption.

.DESCRIPTION
Encrypt-Decrypt is a cmdlet that provides functionality to encrypt or decrypt files or strings using AES encryption. It supports two modes: encryption and decryption. When in encryption mode, it encrypts a plaintext string or file. When in decryption mode, it decrypts an encrypted string or file.

.PARAMETER FilePath
Specifies the path to the file to be encrypted or decrypted.

.PARAMETER Encrypt
Indicates that the input will be encrypted. Cannot be used with Decrypt.

.PARAMETER Decrypt
Indicates that the input will be decrypted. Cannot be used with Encrypt.

.PARAMETER EncryptedString
Specifies the encrypted string to be decrypted.

.PARAMETER PlainText
Specifies the plaintext string to be encrypted.

.PARAMETER Password
Specifies the password to be used for encryption or decryption. This parameter is mandatory.

.PARAMETER Salt
Specifies the salt value to be used for key derivation. Default value is "NC2jhdiMm26omW6Z7NsblQ==".

.PARAMETER Iterations
Specifies the number of iterations for key derivation. Default value is 20000.

.EXAMPLE
Encrypt a file using a password and default salt and iterations:
Encrypt-FileString -FilePath "C:\Path\To\File.txt" -Encrypt -Password (Read-Host -AsSecureString)

.EXAMPLE
Decrypt a file using a password and default salt and iterations:
Encrypt-FileString -FilePath "C:\Path\To\EncryptedFile.txt" -Decrypt -Password (Read-Host -AsSecureString)
.EXAMPLE
Encrypt a plaintext string using a password and default salt and iterations:
Encrypt-FileString -PlainText "Hello, world!" -Encrypt -Password (Read-Host -AsSecureString)
.EXAMPLE
Decrypt an encrypted string using a password and default salt and iterations:
Encrypt-FileString -EncryptedString "EncryptedStringHere" -Decrypt -Password (Read-Host -AsSecureString)

.NOTES
    Author: Tim 
    Date: 20.04.2024
    Version: 1.1

Changelog:

V1.0:
    Initial Creation
V1.1:
    Add Support to Encrypt / Decrypt Files
#>

[CmdletBinding(DefaultParameterSetName = 'Encrypt')]
param (
        [Parameter(Mandatory,ParameterSetName = 'File Encrypt')]
        [Parameter(Mandatory,ParameterSetName = 'File Decrypt')]
        [string] $FilePath,

        [Parameter(Mandatory, ParameterSetName = 'Encrypt')]
        [Parameter(Mandatory, ParameterSetName = 'File Encrypt')]
        [switch] $Encrypt,
        
        [Parameter(Mandatory, ParameterSetName = 'Decrypt')]
        [Parameter(Mandatory, ParameterSetName = 'File Decrypt')]
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
        [int32]$Iterations = 20000
) 

# Convert SecureString password to byte array
function ConvertTo-SecureByteArray {
    param(
        [SecureString]$Password
    )

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

# Encrypt bytes using AES encryption
function Get-EncryptedBytes {
    param(
        [byte[]]$Bytes,        
        [byte[]]$Key,
        [byte[]]$Iv
    )

    try {
        $encryptor = $aesAlg.CreateEncryptor($Key, $Iv)

        $msEncrypt = New-Object System.IO.MemoryStream
        $csEncrypt = New-Object System.Security.Cryptography.CryptoStream($msEncrypt, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        # Write the bytes to the crypto stream
        $csEncrypt.Write($Bytes, 0, $Bytes.Length)
        $csEncrypt.FlushFinalBlock() # Flush final block to ensure all data is written
        $csEncrypt.Close()

        # Get the encrypted bytes
        $encryptedBytes = $msEncrypt.ToArray()

        # Convert encrypted bytes to base64 string (for easy representation)
        $encryptedBase64 = [Convert]::ToBase64String($encryptedBytes)
        $encryptedBase64
    }
    catch {
        Write-Output "Something went wrong!"
        Write-Output $_.ErrorDetails.Message
    }
}

# Encrypt a plaintext string
function Get-EncryptedString {
    param(
        [String]$PlainText,
        [byte[]]$Key,
        [byte[]]$Iv
    )

    $PlainTextBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)

    try {
        Get-EncryptedBytes -Bytes $PlainTextBytes -Iv $Iv -Key $Key
    }
    catch {
        Write-Output "Something went wrong!"
        Write-Output $_.ErrorDetails.Message
    }
}

# Encrypts a file using AES encryption and saves it
function Protect-File {
    param(
        [String]$FilePath,
        [byte[]]$Key,
        [byte[]]$Iv
    )

    $PlainTextBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $encryptedBase64 = Get-EncryptedBytes -Bytes $PlainTextBytes -Key $Key -Iv $Iv
    $encryptedBase64 > $FilePath
}

# Decrypt bytes using AES encryption
function Get-DecryptedBytes {
    param(
        [String]$EncryptedString,
        [byte[]]$Key,
        [byte[]]$Iv
    )

    $decryptor = $aesAlg.CreateDecryptor($key, $iv)
    try {
        $encryptedBytes = [Convert]::FromBase64String($EncryptedString)
    }
    catch {
        Write-Output "Incorrect Input!"
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
        Write-Output "Wrong Password!"
        exit 0
    }
}

# Decrypts an encrypted string
function Get-DecryptedString {
    param(
        [String]$EncryptedString,
        [byte[]]$Key,
        [byte[]]$Iv
    )

    Get-DecryptedBytes -EncryptedString $EncryptedString -Key $Key -Iv $Iv
}

# Decrypts an encrypted file and saves the decrypted content
function Unprotect-File {
    param(
        [String]$FilePath,
        [byte[]]$Key,
        [byte[]]$Iv
    )

    $EncryptedString = Get-Content $FilePath
    $DecryptedFile =  Get-DecryptedString -EncryptedString $EncryptedString -Key $Key -Iv $Iv
    $DecryptedFile > $FilePath
}


$PasswordByteArray = ConvertTo-SecureByteArray -Password $Password

# Convert salt to byte array
[byte[]] $SaltBytes = [System.Text.Encoding]::UTF8.GetBytes($Salt)

# Derive key and IV using PBKDF2 with the provided password and salt
[byte[]] $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordByteArray, $SaltBytes, $Iterations).GetBytes(32)
[byte[]] $iv = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordByteArray, $SaltBytes, $Iterations).GetBytes(16)

# Create AES encryption algorithm object
$aesAlg = [System.Security.Cryptography.AesManaged]::Create("aes")


switch($PSCmdlet.ParameterSetName){
    Encrypt{
        Get-EncryptedString -PlainText $PlainText -Key $key -Iv $iv
    }
    Decrypt{
        Get-DecryptedString -EncryptedString $EncryptedString -Key $key -Iv $iv
    }
    'File Encrypt'{
        Protect-File -FilePath $FilePath -Key $key -Iv $iv   
    }    
    'File Decrypt'{
        Unprotect-File -FilePath $FilePath -Key $key -Iv $iv   
    }
}
