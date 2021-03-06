/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend_string.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_secp256k1.h"

#include <secp256k1.h>

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_start, 0)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ecdsa_verify, 0)
    ZEND_ARG_INFO(0, msg32)
    ZEND_ARG_INFO(0, signature)
    ZEND_ARG_INFO(0, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ecdsa_sign, 0)
    ZEND_ARG_INFO(0, msg32)
    ZEND_ARG_INFO(1, signature)
    ZEND_ARG_INFO(1, signatureLen)
    ZEND_ARG_INFO(0, secretKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ecdsa_sign_compact, 0)
    ZEND_ARG_INFO(0, msg32)
    ZEND_ARG_INFO(1, signature)
    ZEND_ARG_INFO(1, signatureLen)
    ZEND_ARG_INFO(0, secretKey)
    ZEND_ARG_INFO(1, recid)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ecdsa_recover_compact, 0)
    ZEND_ARG_INFO(0, msg32)
    ZEND_ARG_INFO(0, signature)
    ZEND_ARG_INFO(0, recid)
    ZEND_ARG_INFO(0, compressed)
    ZEND_ARG_INFO(1, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_seckey_verify, 0)
    ZEND_ARG_INFO(0, secretKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_verify, 0)
    ZEND_ARG_INFO(0, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_create, 0)
    ZEND_ARG_INFO(1, publicKey)
    ZEND_ARG_INFO(1, publicKeyLength)
    ZEND_ARG_INFO(0, secretKey)
    ZEND_ARG_INFO(0, compressed)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_decompress, 0)
    ZEND_ARG_INFO(1, publicKey)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_privkey_import, 0)
    ZEND_ARG_INFO(1, seckey)
    ZEND_ARG_INFO(0, privkey)
    ZEND_ARG_INFO(0, compressed)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_privkey_export, 0)
    ZEND_ARG_INFO(0, seckey)
    ZEND_ARG_INFO(1, derkey)
    ZEND_ARG_INFO(1, derkeylen)
    ZEND_ARG_INFO(0, compressed)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_privkey_tweak_add, 0)
    ZEND_ARG_INFO(1, seckey)
    ZEND_ARG_INFO(0, tweak)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_tweak_add, 0)
    ZEND_ARG_INFO(1, publicKey)
    ZEND_ARG_INFO(0, tweak)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_privkey_tweak_mul, 0)
    ZEND_ARG_INFO(1, seckey)
    ZEND_ARG_INFO(0, tweak)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(arginfo_secp256k1_ec_pubkey_tweak_mul, 0)
    ZEND_ARG_INFO(1, publicKey)
    ZEND_ARG_INFO(0, publicKeyLength)
    ZEND_ARG_INFO(0, tweak)
ZEND_END_ARG_INFO();

void print_string(unsigned char *string, int stringlen)
{
  int i;
  php_printf(" string (%d)\n - ", stringlen);
  for(i=0; i<stringlen; i++) {
    php_printf("%.2x", string[i]);
  }
  php_printf("\n");
}
/**
 *  NOTE: This extension automatically initializes secp256k1 for the
 *  desired operation - you don't need to call this yourself.
 *
 *  Initialize the library. This may take some time (10-100 ms).
 *  You need to call this before calling any other function.
 *  It cannot run in parallel with any other functions, but once
 *  secp256k1_start() returns, all other functions are thread-safe.
 */
PHP_FUNCTION(secp256k1_start) {
    long mode;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &mode) == FAILURE) {
        return;
    }

    secp256k1_start(mode);
}

/** Free all memory associated with this library. After this, no
 *  functions can be called anymore, except secp256k1_start()
 */
PHP_FUNCTION(secp256k1_stop) {
    secp256k1_stop();
}

/**
 * Verify an ECDSA signature. (Tested)
 *
 * Returns: 1: correct signature
 * 0: incorrect signature
 * -1: invalid public key
 * -2: invalid signature
 *
 * In: msg32: the 32-byte message hash being verified (cannot be NULL)
 * sig: the signature being verified (cannot be NULL)
 * pubkey: the public key to verify with (cannot be NULL)
 * Requires starting using SECP256K1_START_VERIFY.
 */
PHP_FUNCTION(secp256k1_ecdsa_verify) {
    secp256k1_start(SECP256K1_START_VERIFY);

    unsigned char *msg32, *sig, *pubkey;
    int msg32len, siglen, pubkeylen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &msg32, &msg32len, &sig, &siglen, &pubkey, &pubkeylen) == FAILURE) {
        return;
    }

    int result;
    result = secp256k1_ecdsa_verify(msg32, sig, siglen, pubkey, pubkeylen);

    RETURN_LONG(result);
}

/** Create an ECDSA signature.
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, the private key was invalid, or there is not
 *              enough space in the signature (as indicated by siglen).
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
 *  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
 *  In/Out:  siglen: pointer to an int with the length of sig, which will be updated
 *                   to contain the actual signature length (<=72). If 0 is returned, this will be
 *                   set to zero.
 *
 * The sig always has an s value in the lower half of the range (From 0x1
 * to 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
 * inclusive), unlike many other implementations.
 * With ECDSA a third-party can can forge a second distinct signature
 * of the same message given a single initial signature without knowing
 * the key by setting s to its additive inverse mod-order, 'flipping' the
 * sign of the random point R which is not included in the signature.
 * Since the forgery is of the same message this isn't universally
 * problematic, but in systems where message malleability or uniqueness
 * of signatures is important this can cause issues.  This forgery can be
 * blocked by all verifiers forcing signers to use a canonical form. The
 * lower-S form reduces the size of signatures slightly on average when
 * variable length encodings (such as DER) are used and is cheap to
 * verify, making it a good choice. Security of always using lower-S is
 * assured because anyone can trivially modify a signature after the
 * fact to enforce this property.  Adjusting it inside the signing
 * function avoids the need to re-serialize or have curve specific
 * constants outside of the library.  By always using a canonical form
 * even in applications where it isn't needed it becomes possible to
 * impose a requirement later if a need is discovered.
 * No other forms of ECDSA malleability are known and none seem likely,
 * but there is no formal proof that ECDSA, even with this additional
 * restriction, is free of other malleability.  Commonly used serialization
 * schemes will also accept various non-unique encodings, so care should
 * be taken when this property is required for an application.
 */
PHP_FUNCTION(secp256k1_ecdsa_sign) {
    secp256k1_start(SECP256K1_START_SIGN);

    zval *signature, *signatureLen;
    unsigned char *seckey, *msg32;
    int seckeylen, msg32len;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "szzs", &msg32, &msg32len, &signature, &signatureLen, &seckey, &seckeylen) == FAILURE) {
       return;
    }

    unsigned char newsig[70];
    int newsiglen, result;
    result = secp256k1_ecdsa_sign(msg32, newsig, &newsiglen, seckey, NULL, NULL);

    if (result) {
        ZVAL_STRINGL(signature, newsig, newsiglen, 1);
        ZVAL_LONG(signatureLen, newsiglen);
    }

    RETURN_LONG(result);
}

/** Create a compact ECDSA signature (64 byte + recovery id).
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the secret key was invalid.
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
 *  Out:     sig:    pointer to a 64-byte array where the signature will be placed (cannot be NULL)
 *                   In case 0 is returned, the returned signature length will be zero.
 *           recid:  pointer to an int, which will be updated to contain the recovery id (can be NULL)
 */
PHP_FUNCTION(secp256k1_ecdsa_sign_compact) {
    secp256k1_start(SECP256K1_START_SIGN);

    unsigned char *seckey, *msg32;
    int seckeylen, msg32len;
    zval *signature, *signatureLen, *recid;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "szzsz", &msg32, &msg32len, &signature, &signatureLen, &seckey, &seckeylen, &recid) == FAILURE) {
       return;
    }

    unsigned char newsig[64];
    int newsiglen, newrecid, result;
    result = secp256k1_ecdsa_sign_compact(msg32, newsig, seckey, NULL, NULL, &newrecid);

    if (result) {
        newsig[newsiglen] = 0U;
        ZVAL_STRINGL(signature, newsig, 64, 1);
        ZVAL_LONG(signatureLen, 64);
        ZVAL_LONG(recid, newrecid);
    }

    RETURN_LONG(result);
}

/** Recover an ECDSA public key from a compact signature.
 *  Returns: 1: public key successfully recovered (which guarantees a correct signature).
 *           0: otherwise.
 *  In:      msg32:      the 32-byte message hash assumed to be signed (cannot be NULL)
 *           sig64:      signature as 64 byte array (cannot be NULL)
 *           compressed: whether to recover a compressed or uncompressed pubkey
 *           recid:      the recovery id (0-3, as returned by ecdsa_sign_compact)
 *  Out:     pubkey:     pointer to a 33 or 65 byte array to put the pubkey (cannot be NULL)
 *           pubkeylen:  pointer to an int that will contain the pubkey length (cannot be NULL)
 *
 * => secp256k1_ecdsa_recover_compact($msg32, $signature, $recid, $compressed, $publicKey)
 */
PHP_FUNCTION(secp256k1_ecdsa_recover_compact) {
    secp256k1_start(SECP256K1_START_VERIFY);

    unsigned char *msg32, *signature;
    int msg32len, signatureLen, compressed, recid;
    zval *publicKey;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssllz", &msg32, &msg32len, &signature, &signatureLen, &recid, &compressed, &publicKey) == FAILURE) {
       return;
    }

    unsigned char newpubkey[(compressed ? 33 : 65)];
    int newpubkeylen, result;
    result = secp256k1_ecdsa_recover_compact(msg32, signature, newpubkey, &newpubkeylen, compressed, recid);

    if (result) {
        ZVAL_STRINGL(publicKey, newpubkey, newpubkeylen, 1);
    }

    RETURN_LONG(result);
}

/** Verify an ECDSA secret key.
 *  Returns: 1: secret key is valid
 *           0: secret key is invalid
 *  In:      seckey: pointer to a 32-byte secret key (cannot be NULL)
 */
PHP_FUNCTION(secp256k1_ec_seckey_verify) {
    unsigned char *seckey;
    int seckeylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &seckey, &seckeylen) == FAILURE) {
        return;
    }

    int result;
    result = secp256k1_ec_seckey_verify(seckey);

    RETURN_LONG(result);
}

/** Just validate a public key.
 *  Returns: 1: valid public key
 *           0: invalid public key
 *  In:      pubkey:    pointer to a 33-byte or 65-byte public key (cannot be NULL).
 *           pubkeylen: length of pubkey
 */
PHP_FUNCTION(secp256k1_ec_pubkey_verify) {
    secp256k1_start(SECP256K1_START_SIGN);

    unsigned char *pubkey;
    int pubkeylen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &pubkey, &pubkeylen) == FAILURE) {
        return;
    }

    int result;
    result = secp256k1_ec_pubkey_verify(pubkey, pubkeylen);

    RETURN_LONG(result);
}

/** Compute the public key for a secret key. (Tested)
 *  In:     compressed: whether the computed public key should be compressed
 *          seckey:     pointer to a 32-byte private key (cannot be NULL)
 *  Out:    pubkey:     pointer to a 33-byte (if compressed) or 65-byte (if uncompressed)
 *                      area to store the public key (cannot be NULL)
 *          pubkeylen:  pointer to int that will be updated to contains the pubkey's
 *                      length (cannot be NULL)
 *  Returns: 1: secret was valid, public key stored
 *           0: secret was invalid, try again.
 */
PHP_FUNCTION(secp256k1_ec_pubkey_create) {
    secp256k1_start(SECP256K1_START_SIGN);

    zval *pubkey, *pubkeylen;
    unsigned char *seckey;
    int seckeylen, compressed;
    int newpubkeylen = 65;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zzsl", &pubkey, &pubkeylen, &seckey, &seckeylen, &compressed) == FAILURE) {
        return;
    }

    unsigned char newpubkey[compressed ? 33 : 65];
    int result;
    result = secp256k1_ec_pubkey_create(newpubkey, &newpubkeylen, seckey, compressed);

    if (result) {
        newpubkey[newpubkeylen] = 0U;
        ZVAL_STRINGL(pubkey, newpubkey, newpubkeylen, 1);
        ZVAL_LONG(pubkeylen, newpubkeylen);
    }

    RETURN_LONG(result);
}

/** Decompress a public key. (Tested, but hidden SEG FAULT somewhere..)
 * In/Out: pubkey:    pointer to a 65-byte array to put the decompressed public key.
                      It must contain a 33-byte or 65-byte public key already (cannot be NULL)
 *         pubkeylen: pointer to the size of the public key pointed to by pubkey (cannot be NULL)
                      It will be updated to reflect the new size.
 * Returns: 0 if the passed public key was invalid, 1 otherwise. If 1 is returned, the
            pubkey is replaced with its decompressed version.
 */
PHP_FUNCTION(secp256k1_ec_pubkey_decompress) {
    secp256k1_start(SECP256K1_START_SIGN);

    zval *zPubKey;
    unsigned char *pubkey, newpubkey[65];
    int pubkeylen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z/", &zPubKey) == FAILURE) {
        return;
    }

    pubkey = Z_STRVAL_P(zPubKey);
    pubkeylen = Z_STRLEN_P(zPubKey);
    memcpy(newpubkey, pubkey, pubkeylen);
    int result;
    result = secp256k1_ec_pubkey_decompress(newpubkey, &pubkeylen);

    if (result == 1) {
        ZVAL_STRINGL(zPubKey, newpubkey, pubkeylen, 1);
    }

    RETURN_LONG(result);
}

/** Import a private key in DER dormat. */
PHP_FUNCTION (secp256k1_ec_privkey_import) {

    zval *seckey;
    unsigned char *privkey, *newseckey;
    int privkeylen;
    long compressed;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zsl", &seckey, &privkey, &privkeylen, &compressed) == FAILURE) {
        return;
    }

    int result;
    result = secp256k1_ec_privkey_import(newseckey, privkey, compressed);

    if (result) {
        newseckey[32] = 0U;
        ZVAL_STRING(seckey, newseckey, 1);
    }

    RETURN_LONG(result);
}

/** Export a private key in DER format. */
PHP_FUNCTION (secp256k1_ec_privkey_export) {
    zval *derkey, *derkeylen;
    unsigned char *seckey, *newkey;
    int seckeylen, newkeylen, compressed;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "szzl", &seckey, &seckeylen, &derkey, &derkeylen, &compressed) == FAILURE) {
        return;
    }

    newkey = Z_STRVAL_P(derkey);
    newkeylen = Z_LVAL_P(derkeylen);
    int result;
    result = secp256k1_ec_privkey_export(seckey, newkey, &newkeylen, compressed);

    if (result) {
        newkey[newkeylen] = 0U;
        ZVAL_STRINGL(derkey, newkey, newkeylen, 0);
        ZVAL_LONG(derkeylen, newkeylen);
    }

    RETURN_LONG(result);
}

/** Tweak a private key by adding tweak to it. (Tested) */
PHP_FUNCTION (secp256k1_ec_privkey_tweak_add) {

    zval *seckey;
    unsigned char *newseckey, *tweak;
    int tweaklen;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &seckey, &tweak, &tweaklen) == FAILURE) {
        return;
    }

    newseckey = Z_STRVAL_P(seckey);
    int result;
    result = secp256k1_ec_privkey_tweak_add(newseckey, tweak);

    if (result) {
        newseckey[32] = 0U;
        Z_STRVAL_P(seckey) = newseckey;
        Z_STRLEN_P(seckey) = 32;
    }

    RETURN_LONG(result);
}

/** Tweak a public key by adding tweak times the generator to it (Tested) */
PHP_FUNCTION (secp256k1_ec_pubkey_tweak_add) {
    secp256k1_start(SECP256K1_START_VERIFY);

    zval *pubkey;
    unsigned char  *tweak, *newpubkey;
    int tweaklen, newpubkeylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &pubkey, &tweak, &tweaklen) == FAILURE) {
        return;
    }

    newpubkey = Z_STRVAL_P(pubkey);
    newpubkeylen = Z_STRLEN_P(pubkey);
    int result;
    result = secp256k1_ec_pubkey_tweak_add(newpubkey, newpubkeylen, tweak);

    if (result) {
        newpubkey[newpubkeylen] = 0U;
        ZVAL_STRINGL(pubkey, newpubkey, newpubkeylen, 0);
    }

    RETURN_LONG(result);
}

/** Tweak a private key by multiplying it with tweak. (Tested) */
PHP_FUNCTION (secp256k1_ec_privkey_tweak_mul) {

    zval *seckey;
    unsigned char *newseckey, *tweak;
    int tweaklen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &seckey, &tweak, &tweaklen) == FAILURE) {
        return;
    }

    newseckey = Z_STRVAL_P(seckey);
    int result;
    result = secp256k1_ec_privkey_tweak_mul(newseckey, tweak);

    if (result) {
        newseckey[32] = 0U;
        Z_STRVAL_P(seckey) = newseckey;
        Z_STRLEN_P(seckey) = 32;
    }

    RETURN_LONG(result);
}

/** Tweak a public key by multiplying it with tweak (Tested) */
PHP_FUNCTION (secp256k1_ec_pubkey_tweak_mul) {
    secp256k1_start(SECP256K1_START_VERIFY);

    zval *pubkey;
    int pubkeylen;
    unsigned char *tweak, *newpubkey;
    int tweaklen, newpubkeylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zls", &pubkey, &pubkeylen, &tweak, &tweaklen) == FAILURE) {
        return;
    }

    newpubkey = Z_STRVAL_P(pubkey);
    newpubkeylen = Z_STRLEN_P(pubkey);
    int result;
    result = secp256k1_ec_pubkey_tweak_mul(newpubkey, pubkeylen, tweak);

    if (result) {
        newpubkey[pubkeylen] = 0U;
        ZVAL_STRINGL(pubkey, newpubkey, newpubkeylen, 0);
    }

    RETURN_LONG(result);
}

PHP_MINIT_FUNCTION(secp256k1) {

    REGISTER_LONG_CONSTANT("SECP256K1_START_VERIFY", SECP256K1_START_VERIFY, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SECP256K1_START_SIGN", SECP256K1_START_SIGN, CONST_CS | CONST_PERSISTENT);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(secp256k1) {
    return SUCCESS;
}

/* Remove if there's nothing to do at request start */
PHP_RINIT_FUNCTION(secp256k1) {
    return SUCCESS;
}

/* Remove if there's nothing to do at request end */
PHP_RSHUTDOWN_FUNCTION(secp256k1) {
    return SUCCESS;
}

PHP_MINFO_FUNCTION(secp256k1) {
    php_info_print_table_start();
    php_info_print_table_header(2, "secp256k1 support", "enabled");
    php_info_print_table_end();
}

/* {{{ secp256k1_functions[]
 *
 * Every user visible function must have an entry in secp256k1_functions[].
 */
const zend_function_entry secp256k1_functions[] = {
    PHP_FE(secp256k1_start, arginfo_secp256k1_start)
    PHP_FE(secp256k1_stop, NULL)
    PHP_FE(secp256k1_ecdsa_sign, arginfo_secp256k1_ecdsa_sign)
    PHP_FE(secp256k1_ecdsa_verify, arginfo_secp256k1_ecdsa_verify)
    PHP_FE(secp256k1_ecdsa_sign_compact, arginfo_secp256k1_ecdsa_sign_compact)
    PHP_FE(secp256k1_ecdsa_recover_compact, arginfo_secp256k1_ecdsa_recover_compact)
    PHP_FE(secp256k1_ec_seckey_verify, arginfo_secp256k1_ec_seckey_verify)
    PHP_FE(secp256k1_ec_pubkey_verify, arginfo_secp256k1_ec_pubkey_verify)
    PHP_FE(secp256k1_ec_pubkey_create, arginfo_secp256k1_ec_pubkey_create)
    PHP_FE(secp256k1_ec_pubkey_decompress, arginfo_secp256k1_ec_pubkey_decompress)
    PHP_FE(secp256k1_ec_privkey_import, arginfo_secp256k1_ec_privkey_import)
    PHP_FE(secp256k1_ec_privkey_export, arginfo_secp256k1_ec_privkey_export)
    PHP_FE(secp256k1_ec_privkey_tweak_add, arginfo_secp256k1_ec_privkey_tweak_add)
    PHP_FE(secp256k1_ec_privkey_tweak_mul, arginfo_secp256k1_ec_privkey_tweak_mul)
    PHP_FE(secp256k1_ec_pubkey_tweak_add, arginfo_secp256k1_ec_pubkey_tweak_add)
    PHP_FE(secp256k1_ec_pubkey_tweak_mul, arginfo_secp256k1_ec_pubkey_tweak_mul)
    PHP_FE_END /* Must be the last line in secp256k1_functions[] */
};

zend_module_entry secp256k1_module_entry = {
    STANDARD_MODULE_HEADER,
    "secp256k1",
    secp256k1_functions,
    PHP_MINIT(secp256k1),
    PHP_MSHUTDOWN(secp256k1),
    PHP_RINIT(secp256k1), /* Replace with NULL if there's nothing to do at request start */
    PHP_RSHUTDOWN(secp256k1), /* Replace with NULL if there's nothing to do at request end */
    PHP_MINFO(secp256k1),
    PHP_SECP256K1_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SECP256K1
ZEND_GET_MODULE(secp256k1)
#endif
