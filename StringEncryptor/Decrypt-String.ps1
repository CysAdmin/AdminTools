param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$EncryptedString,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [securestring] $Password,

        [ValidateNotNullOrEmpty()]
        [string]$Salt = "NC2jhdiMm26omW6Z7NsblQ==",

        [ValidateNotNullOrEmpty()]
        [int32]$Iterations = 2000
)
# Create AES encryption algorithm object
$aesAlg = [System.Security.Cryptography.AesManaged]::Create("aes")

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
}
finally {
    # Free memory allocated for SecureString
    [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
}

# Convert salt to byte array
[byte[]] $saltBytes = [System.Text.Encoding]::UTF8.GetBytes($Salt)

# Derive key and IV using PBKDF2 with the provided password and salt
[byte[]] $key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordByteArray, $saltBytes, $Iterations).GetBytes(32)
[byte[]] $iv = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordByteArray, $saltBytes, $Iterations).GetBytes(16)

# Create decryptor object
$decryptor = $aesAlg.CreateDecryptor($key, $iv)

# Convert encrypted string from base64 to byte array
$encryptedBytes = [Convert]::FromBase64String($EncryptedString)

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
}
