/* $Id$ */

#ifndef PHP_SECP256K1_H
#define PHP_SECP256K1_H

extern zend_module_entry secp256k1_module_entry;
#define phpext_secp256k1_ptr &secp256k1_module_entry

#define PHP_SECP256K1_VERSION "0.1.0"

PHP_FUNCTION(secp256k1_start);
PHP_FUNCTION(secp256k1_stop);
PHP_FUNCTION(secp256k1_ecdsa_verify);
PHP_FUNCTION(secp256k1_ecdsa_sign);
PHP_FUNCTION(secp256k1_ec_seckey_verify);
PHP_FUNCTION(secp256k1_ec_pubkey_verify);
PHP_FUNCTION(secp256k1_ec_pubkey_create);
PHP_FUNCTION(secp256k1_ec_pubkey_decompress);
PHP_FUNCTION(secp256k1_ec_privkey_import);
PHP_FUNCTION(secp256k1_ec_privkey_export);
PHP_FUNCTION(secp256k1_ec_privkey_tweak_add);
PHP_FUNCTION(secp256k1_ec_privkey_tweak_mul);
PHP_FUNCTION(secp256k1_ec_pubkey_tweak_add);
PHP_FUNCTION(secp256k1_ec_pubkey_tweak_mul);

#endif	/* PHP_SECP256K1_H */
