param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]

        [securestring]$Password,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]

        [string]$PlainText,        
        [ValidateNotNullOrEmpty()]
        [string]$Salt = "NC2jhdiMm26omW6Z7NsblQ==",

        [ValidateNotNullOrEmpty()]
        [int32]$Iterations = 2000
)

$aesAlg = [System.Security.Cryptography.AesManaged]::Create("aes")
# Convert salt to bytes
$saltBytes = [System.Text.Encoding]::UTF8.GetBytes($Salt)

$Ptr = [System.Security.SecureStringMarshal]::SecureStringToGlobalAllocUnicode($Password)
$CharArray = @()
$PasswordByteArray = @()
    try {
        $CharArray = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr) -split ""
        foreach ($Char in $CharArray) {
            $PasswordByteArray += [System.Text.Encoding]::Unicode.GetBytes($Char)
        }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
    }

# Generate key and IV using PBKDF2
$key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordByteArray, $saltBytes, $Iterations).GetBytes(32)
$iv = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordByteArray, $saltBytes, $Iterations).GetBytes(16)

# Create an encryptor
$encryptor = $aesAlg.CreateEncryptor($key, $iv)

# Convert the plaintext string to bytes
$PlainTextBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)

try {
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



