# encrypt
Library to help encrypt/decrypt text

# Usage

```
$aes = new \Kronos\Encrypt\Cipher\AES();

$kms_client = new \Aws\Kms\KmsClient([
      'credentials' => [
              'key' => 'AWS user key',
              'secret' => 'AWS user secret',
      ],
      'region' => "us-east-1",
      'version' => 'latest',
]);

$key = new \Kronos\Encrypt\KeyProvider\KMS\KeyDescription();
$key->ciphertextBlob = "Base64EncodedCiphertextBlob";

$kms = new \Kronos\Encrypt\KeyProvider\KMS($kms_client, $key);

$service = new \Kronos\Encrypt\TextCrypt($aes, $kms);
echo $service->decrypt($service->encrypt(file_get_contents($argv[1])));
```