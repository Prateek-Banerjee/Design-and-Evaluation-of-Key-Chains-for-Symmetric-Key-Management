CREATE TABLE "persistent_derivation" (
	"persistent_derivation_for_prg_sec_param_16" BLOB,
	"persistent_derivation_for_prg_sec_param_24" BLOB,
	"persistent_derivation_for_prg_sec_param_32" BLOB,
	"persistent_derivation_for_hkdf_sha256"	BLOB,
	"persistent_derivation_for_hkdf_sha3_256" BLOB,
	"persistent_derivation_for_hkdf_sha512"	BLOB,
	"persistent_derivation_for_hkdf_sha3_512" BLOB,
	"persistent_derivation_for_shake128_xdrbg" BLOB,
	"persistent_derivation_for_shake256_xdrbg" BLOB,
	"persistent_derivation_for_ascon_xdrbg"	BLOB
);

INSERT INTO "persistent_derivation" (
    "persistent_derivation_for_prg_sec_param_16",
    "persistent_derivation_for_prg_sec_param_24",
    "persistent_derivation_for_prg_sec_param_32",
    "persistent_derivation_for_hkdf_sha256",
    "persistent_derivation_for_hkdf_sha3_256",
    "persistent_derivation_for_hkdf_sha512",
    "persistent_derivation_for_hkdf_sha3_512",
    "persistent_derivation_for_shake128_xdrbg",
    "persistent_derivation_for_shake256_xdrbg",
    "persistent_derivation_for_ascon_xdrbg"
) VALUES ("b''","b''","b''","b''","b''","b''","b''","b''","b''","b''");
