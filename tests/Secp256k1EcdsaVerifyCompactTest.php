<?php

namespace BitWasp\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1EcdsaVerifyCompactTest extends TestCase
{
    public function testRubenSign()
    {
        $privkey = $this->toBinary32("17a2209250b59f07a25b560aa09cb395a183eb260797c0396b82904f918518d5");
        $msg32 = "vires is numeris";
        $expectedSignature = "00dcc16a9afb34b2d788622841d41be36bfe87314aecf8186ae096ee686219724f833b219b53dc0a4fe8d49511fff42b8ccb2d59379f96fb59d2ed56263ba0f3";
        
        $signature = '';
        $signatureLength = 0;
        $recid = 0;
        
        $this->assertEquals(1, secp256k1_ecdsa_sign_compact($msg32, $signature, $signatureLength, $privkey, $recid));
        $this->assertEquals($expectedSignature, bin2hex($signature));

        $pubkey = '';
        $pubkeylen = 0;
        $compressed = 1;
        $this->assertEquals(1, secp256k1_ec_pubkey_create($pubkey, $pubkeylen, $privkey, $compressed));
        $this->assertEquals(1, secp256k1_ecdsa_recover_compact($msg32, $signature, $recid, $compressed, $pubkey));
    }
    
    public function testRubenVerify()
    {
        $expectedPublickey = "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6";
        $message = "vires is numeris";
        $signature = "G8JawPtQOrybrSP1WHQnQPr67B9S3qrxBrl1mlzoTJOSHEpmnF7D3+t+LX0Xei9J20B5AIdPbeL3AaTBZ4N3bY0=";
        $address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
        $recid = 0;
        $publicKey = "";
        
        $messageHash = hex2bin("88630588cd15244c180c7dee585b64278907703fd086e8f4cebec2daf3de28d3");
        
        $signature = base64_decode($signature, true);
        $recoveryFlags = ord($signature[0]) - 27;
        
        $compressed = ($recoveryFlags & 4) != 0;
        $recid = ($recoveryFlags & 3);
        
        $signature = substr($signature, 1);
        
        $this->assertEquals(1, secp256k1_ecdsa_recover_compact($messageHash, $signature, $recid, $compressed, $publicKey));
        $this->assertEquals($expectedPublickey, bin2hex($publicKey));
    }
}
