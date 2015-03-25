<?php

namespace {

    /**
     * @param string $msg32
     * @param string $signature
     * @param integer $signatureLength
     * @param string $privateKey
     * @return int
     */
    function secp256k1_ecdsa_sign($msg32, $signature, $signatureLength, $privateKey)
    {
    }

    /**
     * @param string $msg32
     * @param string $signature
     * @param string $privateKey
     * @param integer $recid
     * @return int
     */
    function secp256k1_ecdsa_sign_compact($msg32, $signature, $privateKey, $recid)
    {
    }

    /**
     * @param string $msg32
     * @param string $signature
     * @param string $publicKey
     * @return int
     */
    function secp256k1_ecdsa_verify($msg32, $signature, $publicKey)
    {
    }

    /**
     * @param string $msg32
     * @param string $signature
     * @param string $pubkey
     * @param int $recoveryId
     * @return int
     */
    function secp256k1_ecdsa_recover_compact($msg32, $signature, $pubkey, $recoveryId)
    {
    }

    /**
     * @param $publicKey
     * @param $publicKeyLen
     * @param $secretKey
     * @param $compressed
     * @return int
     */
    function secp256k1_ec_pubkey_create($publicKey, $publicKeyLen, $secretKey, $compressed)
    {
    }

    /**
     * @param string $privateKey
     * @param string $tweak
     * @return int
     */
    function secp256k1_ec_privkey_tweak_add($privateKey, $tweak)
    {
    }

    /**
     * @param string $privateKey
     * @param string $tweak
     * @return int
     */
    function secp256k1_ec_privkey_tweak_mul($privateKey, $tweak)
    {
    }

    /**
     * @param string $publicKey
     * @param string $tweak
     * @return int
     */
    function secp256k1_ec_pubkey_tweak_add($publicKey, $tweak)
    {
    }

    /**
     * @param string $publicKey
     * @param string $pubkeyLen
     * @param string $tweak
     * @return int
     */
    function secp256k1_ec_pubkey_tweak_mul($publicKey, $pubkeyLen, $tweak)
    {
    }

    /**
     * @param string $publicKey
     * @return int
     */
    function secp256k1_ec_pubkey_verify($publicKey)
    {

    }

    /**
     * @param string $secKey
     * @return int
     */
    function secp256k1_ec_seckey_verify($secKey)
    {

    }
}
