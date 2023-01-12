use bitcoin::bech32::{decode, encode, u5, FromBase32, ToBase32, Variant};
use crypto::digest::Digest;
use crypto::ripemd160::Ripemd160;
use crypto::sha2::Sha256;

pub use ed25519_dalek::PublicKey as Ed25519;
use serde::{Deserialize, Serialize};

use crate::error::BootError;
static BECH32_PUBKEY_DATA_PREFIX_SECP256K1: [u8; 5] = [0xeb, 0x5a, 0xe9, 0x87, 0x21]; // "eb5ae98721";
static BECH32_PUBKEY_DATA_PREFIX_ED25519: [u8; 5] = [0x16, 0x24, 0xde, 0x64, 0x20]; // "eb5ae98721";

#[derive(Deserialize, Serialize, Debug, Clone)]
/// The public key we used to generate the cosmos/tendermind/terrad addresses
pub struct PublicKey {
    /// This is optional as we can generate non-pub keys without
    pub raw_pub_key: Option<Vec<u8>>,
    /// The raw bytes used to generate non-pub keys
    pub raw_address: Option<Vec<u8>>,
}
/*
upgrade eventually to support
Variant::Bech32M ?
 */
impl PublicKey {
    /// Generate a Cosmos/Tendermint/Terrad Public Key
    pub fn from_bitcoin_public_key(bpub: &bitcoin::util::key::PublicKey) -> PublicKey {
        let bpub_bytes = bpub.inner.serialize();
        //     eprintln!("B-PK-{}", hex::encode(bpub_bytes));
        let raw_pub_key = PublicKey::pubkey_from_public_key(&bpub_bytes);
        let raw_address = PublicKey::address_from_public_key(&bpub_bytes);

        PublicKey {
            raw_pub_key: Some(raw_pub_key),
            raw_address: Some(raw_address),
        }
    }
    /// Generate from secp256k1 Cosmos/Terrad Public Key
    pub fn from_public_key(bpub: &[u8]) -> PublicKey {
        let raw_pub_key = PublicKey::pubkey_from_public_key(bpub);
        let raw_address = PublicKey::address_from_public_key(bpub);

        PublicKey {
            raw_pub_key: Some(raw_pub_key),
            raw_address: Some(raw_address),
        }
    }
    /// Generate a Cosmos/Tendermint/Terrad Account
    pub fn from_account(acc_address: &str, prefix: &str) -> Result<PublicKey, BootError> {
        PublicKey::check_prefix_and_length(prefix, acc_address, 44).and_then(|vu5| {
            let vu8 = Vec::from_base32(vu5.as_slice()).map_err(|source| BootError::Conversion {
                key: acc_address.into(),
                source,
            })?;
            Ok(PublicKey {
                raw_pub_key: None,
                raw_address: Some(vu8),
            })
        })
    }
    /// build a public key from a tendermint public key
    pub fn from_tendermint_key(tendermint_public_key: &str) -> Result<PublicKey, BootError> {
        // Len 83 == PubKeySecp256k1 key with a prefix of 0xEB5AE987
        // Len 82 == PubKeyEd25519 key with a prefix of 0x1624DE64

        let len = tendermint_public_key.len();
        if len == 83 {
            PublicKey::check_prefix_and_length("terravalconspub", tendermint_public_key, len)
                .and_then(|vu5| {
                    let vu8 = Vec::from_base32(vu5.as_slice()).map_err(|source| {
                        BootError::Conversion {
                            key: tendermint_public_key.into(),
                            source,
                        }
                    })?;
                    log::debug!("{:#?}", hex::encode(&vu8));
                    if vu8.starts_with(&BECH32_PUBKEY_DATA_PREFIX_SECP256K1) {
                        let public_key = PublicKey::public_key_from_pubkey(&vu8)?;
                        let raw = PublicKey::address_from_public_key(&public_key);

                        Ok(PublicKey {
                            raw_pub_key: Some(vu8),
                            raw_address: Some(raw),
                        })
                    } else {
                        Err(BootError::ConversionSECP256k1)
                    }
                })
        } else if len == 82 {
            //  eprintln!("ED25519 keys are not currently supported");
            // todo!()

            PublicKey::check_prefix_and_length("terravalconspub", tendermint_public_key, len)
                .and_then(|vu5| {
                    let vu8 = Vec::from_base32(vu5.as_slice()).map_err(|source| {
                        BootError::Conversion {
                            key: tendermint_public_key.into(),
                            source,
                        }
                    })?;
                    //   log::debug!("{:#?}", hex::encode(&vu8));
                    log::info!("ED25519 public keys are not fully supported");
                    if vu8.starts_with(&BECH32_PUBKEY_DATA_PREFIX_ED25519) {
                        //   let public_key = PublicKey::pubkey_from_ed25519_public_key(&vu8);
                        let raw = PublicKey::address_from_public_ed25519_key(&vu8)?;
                        Ok(PublicKey {
                            raw_pub_key: Some(vu8),
                            raw_address: Some(raw),
                        })
                    } else {
                        //     eprintln!("{}", hex::encode(&vu8));
                        Err(BootError::ConversionED25519)
                    }
                })

            /* */
        } else {
            Err(BootError::ConversionLength(len))
        }
    }
    /// build a terravalcons address from a tendermint hex key
    /// the tendermint_hex_address should be a hex code of 40 length
    pub fn from_tendermint_address(tendermint_hex_address: &str) -> Result<PublicKey, BootError> {
        let len = tendermint_hex_address.len();
        if len == 40 {
            let raw = hex::decode(tendermint_hex_address)?;
            Ok(PublicKey {
                raw_pub_key: None,
                raw_address: Some(raw),
            })
        } else {
            Err(BootError::ConversionLengthED25519Hex(len))
        }
    }
    /// Generate a Operator address for this public key (used by the validator)
    pub fn from_operator_address(valoper_address: &str) -> Result<PublicKey, BootError> {
        PublicKey::check_prefix_and_length("terravaloper", valoper_address, 51).and_then(|vu5| {
            let vu8 = Vec::from_base32(vu5.as_slice()).map_err(|source| BootError::Conversion {
                key: valoper_address.into(),
                source,
            })?;
            Ok(PublicKey {
                raw_pub_key: None,
                raw_address: Some(vu8),
            })
        })
    }

    /// Generate Public key from raw address
    pub fn from_raw_address(raw_address: &str) -> Result<PublicKey, BootError> {
        let vec1 = hex::decode(raw_address)?;

        Ok(PublicKey {
            raw_pub_key: None,
            raw_address: Some(vec1),
        })
    }
    fn check_prefix_and_length(
        prefix: &str,
        data: &str,
        length: usize,
    ) -> Result<Vec<u5>, BootError> {
        let (hrp, decoded_str, _) = decode(data).map_err(|source| BootError::Conversion {
            key: data.into(),
            source,
        })?;
        if hrp == prefix && data.len() == length {
            Ok(decoded_str)
        } else {
            Err(BootError::Bech32DecodeExpanded(
                hrp,
                data.len(),
                prefix.into(),
                length,
            ))
        }
    }
    /**
     * Gets a bech32-words pubkey from a compressed bytes Secp256K1 public key.
     *
     * @param publicKey raw public key
     */
    pub fn pubkey_from_public_key(public_key: &[u8]) -> Vec<u8> {
        [
            BECH32_PUBKEY_DATA_PREFIX_SECP256K1.to_vec(),
            public_key.to_vec(),
        ]
        .concat()
    }
    /**
     * Gets a bech32-words pubkey from a compressed bytes Ed25519 public key.
     *
     * @param publicKey raw public key
     */
    pub fn pubkey_from_ed25519_public_key(public_key: &[u8]) -> Vec<u8> {
        [
            BECH32_PUBKEY_DATA_PREFIX_ED25519.to_vec(),
            public_key.to_vec(),
        ]
        .concat()
    }
    /// Translate from a BECH32 prefixed key to a standard public key
    pub fn public_key_from_pubkey(pub_key: &[u8]) -> Result<Vec<u8>, BootError> {
        if pub_key.starts_with(&BECH32_PUBKEY_DATA_PREFIX_SECP256K1) {
            let len = BECH32_PUBKEY_DATA_PREFIX_SECP256K1.len();
            let len2 = pub_key.len();
            Ok(Vec::from(&pub_key[len..len2]))
        } else if pub_key.starts_with(&BECH32_PUBKEY_DATA_PREFIX_ED25519) {
            let len = BECH32_PUBKEY_DATA_PREFIX_ED25519.len();
            let len2 = pub_key.len();
            let vec = &pub_key[len..len2];
            let ed25519_pubkey = ed25519_dalek::PublicKey::from_bytes(vec)?;
            Ok(ed25519_pubkey.to_bytes().to_vec())
        } else {
            log::info!("pub key does not start with BECH32 PREFIX");
            Err(BootError::Bech32DecodeErr)
        }
    }

    /**
    * Gets a raw address from a compressed bytes public key.
    *
    * @param publicKey raw public key

    */

    pub fn address_from_public_key(public_key: &[u8]) -> Vec<u8> {
        // Vec<bech32::u5> {

        let mut hasher = Ripemd160::new();
        let mut sha = Sha256::new();
        let mut sha_result: [u8; 32] = [0; 32];
        let mut ripe_result: [u8; 20] = [0; 20];
        sha.input(public_key);
        sha.result(&mut sha_result);
        hasher.input(&sha_result);
        hasher.result(&mut ripe_result);
        let address: Vec<u8> = ripe_result.to_vec();
        address
    }
    /**
    * Gets a raw address from a  ed25519 public key.
    *
    * @param publicKey raw public key

    */

    pub fn address_from_public_ed25519_key(public_key: &[u8]) -> Result<Vec<u8>, BootError> {
        // Vec<bech32::u5> {

        if public_key.len() != (32 + 5/* the 5 is the BECH32 ED25519 prefix */) {
            Err(BootError::ConversionPrefixED25519(
                public_key.len(),
                hex::encode(public_key),
            ))
        } else {
            // eprintln!("a_pub_ed_key {}", hex::encode(public_key));
            log::debug!(
                "address_from_public_ed25519_key public key - {}",
                hex::encode(public_key)
            );
            //  let mut hasher = Ripemd160::new();
            let mut sha = Sha256::new();
            let mut sha_result: [u8; 32] = [0; 32];
            //  let mut ripe_result: [u8; 20] = [0; 20];
            // let v = &public_key[5..37];

            sha.input(&public_key[5..]);
            sha.result(&mut sha_result);
            //    hasher.input(public_key);
            //hasher.input(v);
            //    hasher.input(&sha_result);
            //   hasher.result(&mut ripe_result);

            let address: Vec<u8> = sha_result[0..20].to_vec();
            // let address: Vec<u8> = ripe_result.to_vec();
            //     eprintln!("address_from_public_ed_key {}", hex::encode(&address));
            log::debug!(
                "address_from_public_ed25519_key sha result - {}",
                hex::encode(&address)
            );
            Ok(address)
        }
    }
    /// The main account used in most things
    pub fn account(&self, prefix: &str) -> Result<String, BootError> {
        match &self.raw_address {
            Some(raw) => {
                let data = encode(prefix, raw.to_base32(), Variant::Bech32);
                match data {
                    Ok(acc) => Ok(acc),
                    Err(_) => Err(BootError::Bech32DecodeErr),
                }
            }
            None => Err(BootError::Implementation),
        }
    }
    /// The operator address used for validators
    pub fn operator_address(&self, prefix: &str) -> Result<String, BootError> {
        match &self.raw_address {
            Some(raw) => {
                let data = encode(
                    &format!("{}{}", prefix, "valoper"),
                    raw.to_base32(),
                    Variant::Bech32,
                );
                match data {
                    Ok(acc) => Ok(acc),
                    Err(_) => Err(BootError::Bech32DecodeErr),
                }
            }
            None => Err(BootError::Implementation),
        }
    }
    /// application public key - Application keys are associated with a public key terrapub- and an address terra-
    pub fn application_public_key(&self, prefix: &str) -> Result<String, BootError> {
        match &self.raw_pub_key {
            Some(raw) => {
                let data = encode(
                    &format!("{}{}", prefix, "pub"),
                    raw.to_base32(),
                    Variant::Bech32,
                );
                match data {
                    Ok(acc) => Ok(acc),
                    Err(_) => Err(BootError::Bech32DecodeErr),
                }
            }
            None => {
                log::warn!("Missing Public Key. Can't continue");
                Err(BootError::Implementation)
            }
        }
    }
    /// The operator address used for validators public key.
    pub fn operator_address_public_key(&self, prefix: &str) -> Result<String, BootError> {
        match &self.raw_pub_key {
            Some(raw) => {
                let data = encode(
                    &format!("{}{}", prefix, "valoperpub"),
                    raw.to_base32(),
                    Variant::Bech32,
                );
                match data {
                    Ok(acc) => Ok(acc),
                    Err(_) => Err(BootError::Bech32DecodeErr),
                }
            }
            None => Err(BootError::Implementation),
        }
    }
    /// This is a unique key used to sign block hashes. It is associated with a public key terravalconspub.
    pub fn tendermint(&self, prefix: &str) -> Result<String, BootError> {
        match &self.raw_address {
            Some(raw) => {
                let data = encode(
                    &format!("{}{}", prefix, "valcons"),
                    raw.to_base32(),
                    Variant::Bech32,
                );
                match data {
                    Ok(acc) => Ok(acc),
                    Err(_) => Err(BootError::Bech32DecodeErr),
                }
            }
            None => Err(BootError::Implementation),
        }
    }
    /// This is a unique key used to sign block hashes. It is associated with a public key terravalconspub.
    pub fn tendermint_pubkey(&self, prefix: &str) -> Result<String, BootError> {
        match &self.raw_pub_key {
            Some(raw) => {
                // eprintln!("{} - tendermint_pubkey", hex::encode(raw));
                let b32 = raw.to_base32();
                let data = encode(&format!("{}{}", prefix, "valconspub"), b32, Variant::Bech32);
                match data {
                    Ok(acc) => Ok(acc),
                    Err(_) => Err(BootError::Bech32DecodeErr),
                }
            }
            None => Err(BootError::Implementation),
        }
    }
}
#[cfg(test)]
mod tst {
    use super::*;
    #[allow(unused_imports)]
    use env_logger;

    const PREFIX: &str = "terra";

    #[test]
    pub fn tst_conv() -> anyhow::Result<()> {
        let pub_key =
            PublicKey::from_account("terra1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vztv3qqm", PREFIX)?;

        assert_eq!(
            &pub_key.account(PREFIX)?,
            "terra1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vztv3qqm"
        );
        assert_eq!(
            &pub_key.operator_address(PREFIX)?,
            "terravaloper1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vztraasg"
        );
        assert_eq!(
            &pub_key.tendermint(PREFIX)?,
            "terravalcons1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vzlswpuf"
        );
        let x = &pub_key.raw_address.unwrap();
        assert_eq!(hex::encode(x), "94c4c52a9777e3c3628e5cfe819f6e26a7f5bd82");

        Ok(())
    }
    #[test]
    pub fn test_key_conversions() -> anyhow::Result<()> {
        let pub_key = PublicKey::from_public_key(&hex::decode(
            "02cf7ed0b5832538cd89b55084ce93399b186e381684b31388763801439cbdd20a",
        )?);

        assert_eq!(
            &pub_key.operator_address(PREFIX)?,
            "terravaloper1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vztraasg"
        );
        assert_eq!(
            &pub_key.account(PREFIX)?,
            "terra1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vztv3qqm"
        );
        assert_eq!(
            &pub_key.application_public_key(PREFIX)?,
            "terrapub1addwnpepqt8ha594svjn3nvfk4ggfn5n8xd3sm3cz6ztxyugwcuqzsuuhhfq5nwzrf9"
        );
        assert_eq!(
            &pub_key.tendermint_pubkey(PREFIX)?,
            "terravalconspub1addwnpepqt8ha594svjn3nvfk4ggfn5n8xd3sm3cz6ztxyugwcuqzsuuhhfq5z3fguk"
        );

        let x = &pub_key.raw_address.unwrap();
        assert_eq!(hex::encode(x), "94c4c52a9777e3c3628e5cfe819f6e26a7f5bd82");
        let y = pub_key.raw_pub_key.unwrap();
        assert_eq!(
            hex::encode(y),
            "eb5ae9872102cf7ed0b5832538cd89b55084ce93399b186e381684b31388763801439cbdd20a"
        );

        let valconspub_83 =
            "terravalconspub1addwnpepqt8ha594svjn3nvfk4ggfn5n8xd3sm3cz6ztxyugwcuqzsuuhhfq5z3fguk";
        //   eprintln!("{}", hex::encode(&pub_key.raw_pub_key.unwrap()));
        let tendermint_pub_key = PublicKey::from_tendermint_key(valconspub_83)?;
        assert_eq!(
            &tendermint_pub_key.account(PREFIX)?,
            "terra1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vztv3qqm"
        );
        assert_eq!(
            &tendermint_pub_key.application_public_key(PREFIX)?,
            "terrapub1addwnpepqt8ha594svjn3nvfk4ggfn5n8xd3sm3cz6ztxyugwcuqzsuuhhfq5nwzrf9"
        );
        assert_eq!(
            &tendermint_pub_key.tendermint_pubkey(PREFIX)?,
            valconspub_83
        );
        /*
                ED25519 Keys are not currently supported
        */
        // eprintln!("Ed25519 stuff");
        let tendermint_pub_key_ed25519 = PublicKey::from_tendermint_key(
            "terravalconspub1zcjduepqxrwvps0dn88x9s09h6nwrgrpv2vp5dz99309erlp0qmrx8y9ckmq49jx4n",
        )?;

        assert_eq!(
            "terravalconspub1zcjduepqxrwvps0dn88x9s09h6nwrgrpv2vp5dz99309erlp0qmrx8y9ckmq49jx4n",
            &tendermint_pub_key_ed25519.tendermint_pubkey(PREFIX)?
        );
        /*
                assert_eq!(
                    "terravaloper1z5tzp4kdl9h3k29dhp636fy5g97ram29kpxcwh",
                    &tendermint_pub_key_ed25519.operator_address()?
                );

        eprintln!("P2");

        assert_eq!(
            "terra1usws7c2c6cs7nuc8vma9qzaky5pkgvm2uag6rh",
            //"terra1zcjduepqxrwvps0dn88x9s09h6nwrgrpv2vp5dz99309erlp0qmrx8y9ckmqyg0kh0",
            &tendermint_pub_key_ed25519.account()?
        );

         */
        /*
        assert_eq!(
            "terravalcons1usws7c2c6cs7nuc8vma9qzaky5pkgvm2gphml9",
            //            "terravalcons1zcjduepqxrwvps0dn88x9s09h6nwrgrpv2vp5dz99309erlp0qmrx8y9ckmq27ayxy",
            &tendermint_pub_key_ed25519.tendermint()?
        );

          */
        Ok(())
    }
    #[test]
    pub fn test_tendermint() -> anyhow::Result<()> {
        let secp256k1_public_key_str =
            "02A1633CAFCC01EBFB6D78E39F687A1F0995C62FC95F51EAD10A02EE0BE551B5DC";
        let seccp256k1_public_key =
            PublicKey::from_public_key(&hex::decode(secp256k1_public_key_str)?);
        assert_eq!(
            "terrapub1addwnpepq2skx090esq7h7md0r3e76r6ruyet330e904r6k3pgpwuzl92x6actkch6g",
            seccp256k1_public_key.application_public_key(PREFIX)?
        );

        let public_key = "4A25C6640A1F72B9C975338294EF51B6D1C33158BB6ECBA69FBC3FB5A33C9DCE";
        let ed = Ed25519::from_bytes(&hex::decode(public_key)?)?;
        let foo_v8 = PublicKey::pubkey_from_ed25519_public_key(&ed.to_bytes());
        //  let ed2: tendermint::PublicKey =
        //      tendermint::PublicKey::from_raw_ed25519(&hex::decode(public_key)?).unwrap();

        match encode("cosmosvalconspub", foo_v8.to_base32(),Variant::Bech32) {
            Ok(cosmospub) => assert_eq!("cosmosvalconspub1zcjduepqfgjuveq2raetnjt4xwpffm63kmguxv2chdhvhf5lhslmtgeunh8qmf7exk", cosmospub),
            Err(_) => assert!(false, "bad encoding"),
        };
        //   assert_eq!(
        //       "cosmosvalconspub1zcjduepqfgjuveq2raetnjt4xwpffm63kmguxv2chdhvhf5lhslmtgeunh8qmf7exk",
        //       ed2.to_bech32("cosmosvalconspub")
        //   );

        match encode("terravalconspub", foo_v8.to_base32(), Variant::Bech32) {
            Ok(tendermint) => {
                let ed_key = PublicKey::from_tendermint_key(&tendermint)?;
                //let ed_key_pubkey = ed_key.tendermint_pubkey()?;
                let foo = &ed_key.raw_pub_key.unwrap();

                assert_eq!(public_key, hex::encode_upper(&foo[5..]));
            }
            Err(_) => assert!(false, "bad encoding"),
        };
        Ok(())
    }
    #[test]
    pub fn test_proposer() -> anyhow::Result<()> {
        //   dotenv().ok();
        //   env_logger::init();

        let hex_str = "75161033EF6E116BB345F07910A493030B08AD12";
        let cons_str = "terravalcons1w5tpqvl0dcgkhv697pu3pfynqv9s3tgj2d6q6l";
        let cons_pub_str =
            "terravalconspub1zcjduepqpxp3kxmn8yty9eh8a0e6tasdna04q7zsl88u7dyup7fv7t06pl9q342a8t";
        let pk = PublicKey::from_tendermint_key(cons_pub_str)?;
        assert_eq!(cons_str, pk.tendermint(PREFIX)?);
        assert_eq!(hex_str, hex::encode_upper(pk.raw_address.unwrap()));

        let pk2 = PublicKey::from_tendermint_address(hex_str)?;
        assert_eq!(cons_str, &pk2.tendermint(PREFIX)?);
        Ok(())
    }
}
