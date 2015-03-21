<?php

namespace Afk11\Secp256k1Tests;

use Symfony\Component\Yaml\Yaml;

class Secp256k1EcdsaSignTest extends TestCase
{

    /**
     * @return array
     */
    public function getVectors()
    {
        $parser = new Yaml();
        $data = $parser->parse(__DIR__ . '/data/deterministicSignatures.yml');

        $fixtures = [];
        foreach ($data['vectors'] as $vector) {
            $fixtures[] = [$vector['privkey'], $vector['msg'], substr($vector['sig'], 0, strlen($vector['sig'])-2)];
        }
        return $fixtures;
    }

    /**
     * Testing return value 1
     * @dataProvider getVectors
     */
    public function testEcdsaSign($hexPrivKey, $msg, $sig)
    {
        $this->genericTest(
            $hexPrivKey,
            $msg,
            $sig,
            1
        );
    }

    /**
     * @param $privkeyhex
     * @param $msg
     * @param $expectedSig
     * @param $eSigCreate
     */
    private function genericTest($privkeyhex, $msg, $expectedSig, $eSigCreate)
    {
        $privkey = $this->toBinary32($privkeyhex);
        $msg = $this->toBinary32($msg);

        $signature = '';
        $siglen = 0;
        $sign = \secp256k1_ecdsa_sign($msg, $signature, $siglen, $privkey);
        $this->assertEquals($eSigCreate, $sign);
        $this->assertEquals($expectedSig, bin2hex($signature));

        if ($eSigCreate == 1) {
            $pubkey = '';
            $pubkeylen = 0;
            $this->assertEquals(1, secp256k1_ec_pubkey_create($pubkey, $pubkeylen, $privkey, 0));
            $this->assertEquals(1, secp256k1_ecdsa_verify($msg, $signature, $pubkey));
        }
    }
}
