$password = 'FCSupport@2026'
$iterations = 10000
$saltLen = 16
$dkLen = 64

$rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$salt = New-Object byte[] $saltLen
$rand.GetBytes($salt)

function Get-Int32BE($i) {
    $b = [System.BitConverter]::GetBytes([int]$i)
    [array]::Reverse($b)
    return $b
}

function PBKDF2($pwd, $salt, $iters, $dkLen) {
    $hLen = 64
    $blocks = [math]::Ceiling($dkLen / $hLen)
    $dk = New-Object byte[] $dkLen
    for ($i = 1; $i -le $blocks; $i++) {
        $intBytes = Get-Int32BE $i
        $hmac = New-Object System.Security.Cryptography.HMACSHA512 ([System.Text.Encoding]::UTF8.GetBytes($pwd))
        $input = New-Object byte[] ($salt.Length + $intBytes.Length)
        [Array]::Copy($salt, 0, $input, 0, $salt.Length)
        [Array]::Copy($intBytes, 0, $input, $salt.Length, $intBytes.Length)
        $u = $hmac.ComputeHash($input)
        $t = New-Object byte[] $u.Length
        $u.CopyTo($t, 0)
        for ($j = 1; $j -lt $iters; $j++) {
            $u = $hmac.ComputeHash($u)
            for ($k = 0; $k -lt $t.Length; $k++) { $t[$k] = $t[$k] -bxor $u[$k] }
        }
        $offset = ($i - 1) * $hLen
        $copyLen = [Math]::Min($hLen, $dkLen - $offset)
        [Array]::Copy($t, 0, $dk, $offset, $copyLen)
    }
    return $dk
}

$dk = PBKDF2 $password $salt $iterations $dkLen
$salt_b64 = [Convert]::ToBase64String($salt).TrimEnd('=')
$dk_b64 = [Convert]::ToBase64String($dk).TrimEnd('=')
Write-Output "grub.pbkdf2.sha512.$iterations.$salt_b64.$dk_b64"
