use crate::error::BootError;
use bitcoin::util::bip32::{ExtendedPrivKey, IntoDerivationPath};
use bitcoin::Network;

use secp256k1::Secp256k1;

use hkd32::mnemonic::{Phrase, Seed};

use rand_core::OsRng;

use super::public::PublicKey;

/// The Private key structure that is used to generate signatures and public keys
/// WARNING: No Security Audit has been performed
#[derive(Clone)]
pub struct PrivateKey {
    #[allow(missing_docs)]
    pub account: u32,
    #[allow(missing_docs)]
    pub index: u32,
    #[allow(missing_docs)]
    pub coin_type: u32,
    /// The 24 words used to generate this private key
    mnemonic: Option<Phrase>,
    #[allow(dead_code)]
    /// This is used for testing
    root_private_key: ExtendedPrivKey,
    /// The private key
    private_key: ExtendedPrivKey,
}
impl PrivateKey {
    /// Generate a new private key
    pub fn new<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        coin_type: u32,
    ) -> Result<PrivateKey, BootError> {
        let phrase = hkd32::mnemonic::Phrase::random(OsRng, hkd32::mnemonic::Language::English);

        PrivateKey::gen_private_key_phrase(secp, phrase, 0, 0, coin_type, "")
    }
    /// generate a new private key with a seed phrase
    pub fn new_seed<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        seed_phrase: &str,
        coin_type: u32,
    ) -> Result<PrivateKey, BootError> {
        let phrase = hkd32::mnemonic::Phrase::random(OsRng, hkd32::mnemonic::Language::English);

        PrivateKey::gen_private_key_phrase(secp, phrase, 0, 0, coin_type, seed_phrase)
    }
    /// for private key recovery. This is also used by wallet routines to re-hydrate the structure
    pub fn from_words<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        words: &str,
        account: u32,
        index: u32,
        coin_type: u32,
    ) -> Result<PrivateKey, BootError> {
        match hkd32::mnemonic::Phrase::new(words, hkd32::mnemonic::Language::English) {
            Ok(phrase) => {
                PrivateKey::gen_private_key_phrase(secp, phrase, account, index, coin_type, "")
            }
            Err(_) => Err(BootError::Phrasing),
        }
    }

    /// for private key recovery with seed phrase
    pub fn from_words_seed<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        words: &str,
        seed_pass: &str,
        coin_type: u32,
    ) -> Result<PrivateKey, BootError> {
        match hkd32::mnemonic::Phrase::new(words, hkd32::mnemonic::Language::English) {
            Ok(phrase) => {
                PrivateKey::gen_private_key_phrase(secp, phrase, 0, 0, coin_type, seed_pass)
            }
            Err(_) => Err(BootError::Phrasing),
        }
    }

    /// generate the public key for this private key
    pub fn public_key<C: secp256k1::Signing + secp256k1::Context>(
        &self,
        secp: &Secp256k1<C>,
    ) -> PublicKey {
        let x = &self.private_key.private_key.public_key(secp);
        PublicKey::from_bitcoin_public_key(&bitcoin::PublicKey::new(x.clone()))
    }

    pub fn raw_key(&self) -> Vec<u8> {
        self.private_key.private_key.secret_bytes().to_vec()
    }

    fn gen_private_key_phrase<C: secp256k1::Signing + secp256k1::Context>(
        secp: &Secp256k1<C>,
        phrase: Phrase,
        account: u32,
        index: u32,
        coin_type: u32,
        seed_phrase: &str,
    ) -> Result<PrivateKey, BootError> {
        let seed = phrase.to_seed(seed_phrase);
        let root_private_key =
            ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_bytes()).unwrap();
        let path = format!("m/44'/{}'/{}'/0/{}", coin_type, account, index);
        let derivation_path = path.into_derivation_path()?;

        let private_key = root_private_key.derive_priv(secp, &derivation_path)?;
        Ok(PrivateKey {
            account,
            index,
            coin_type,
            mnemonic: Some(phrase),
            root_private_key,
            private_key,
        })
    }

    /// the words used to generate this private key
    pub fn words(&self) -> Option<&str> {
        self.mnemonic.as_ref().map(|phrase| phrase.phrase())
    }

    /// used for testing
    /// could potentially be used to recreate the private key instead of words
    #[allow(dead_code)]
    pub(crate) fn seed(&self, passwd: &str) -> Option<Seed> {
        self.mnemonic.as_ref().map(|phrase| phrase.to_seed(passwd))
    }
}

#[cfg(test)]
mod tst {
    use crate::error::BootError;

    use super::*;

    #[test]
    pub fn tst_gen_mnemonic() -> Result<(), BootError> {
        // this test just makes sure the default will call it.
        let s = Secp256k1::new();
        let coin_type: u32 = 330;
        PrivateKey::new(&s, coin_type).map(|_| ())
    }
    #[test]
    pub fn tst_words() -> anyhow::Result<()> {
        let coin_type: u32 = 330;
        let str_1 = "notice oak worry limit wrap speak medal online prefer cluster roof addict wrist behave treat actual wasp year salad speed social layer crew genius";
        let seed_1 = "a2ae8846397b55d266af35acdbb18ba1d005f7ddbdd4ca7a804df83352eaf373f274ba0dc8ac1b2b25f19dfcb7fa8b30a240d2c6039d88963defc2f626003b2f";
        let s = Secp256k1::new();
        let pk = PrivateKey::from_words(&s, str_1, 0, 0, coin_type)?;
        assert_eq!(hex::encode(pk.seed("").unwrap().as_bytes()), seed_1);
        match pk.words() {
            Some(words) => {
                assert_eq!(words, str_1);
                Ok(())
            }
            None => Err(BootError::MissingPhrase.into()),
        }
    }
    #[test]
    pub fn tst_root_priv_key() -> anyhow::Result<()> {
        let coin_type: u32 = 330;
        let str_1 = "wonder caution square unveil april art add hover spend smile proud admit modify old copper throw crew happy nature luggage reopen exhibit ordinary napkin";
        let secp = Secp256k1::new();
        let pk = PrivateKey::from_words(&secp, str_1, 0, 0, coin_type)?;
        let root_key = "xprv9s21ZrQH143K2ep3BpYRRMjSqjLHZAPAzxfVVS3NBuGKBVtCrK3C8mE8TcmTjYnLm7SJxdLigDFWGAMnctKxc3p5QKNWXdprcFSQzGzQqTW";
        assert_eq!(pk.root_private_key.to_string(), root_key);

        let derived_key = "4804e2bdce36d413206ccf47cc4c64db2eff924e7cc9e90339fa7579d2bd9d5b";
        assert_eq!(
            pk.private_key.private_key.display_secret().to_string(),
            derived_key
        );

        Ok(())
    }
    #[test]
    pub fn tst_words_to_pub() -> anyhow::Result<()> {
        let str_1 = "wonder caution square unveil april art add hover spend smile proud admit modify old copper throw crew happy nature luggage reopen exhibit ordinary napkin";
        let coin_type: u32 = 330;
        let prefix = "terra";
        let secp = Secp256k1::new();
        let pk = PrivateKey::from_words(&secp, str_1, 0, 0, coin_type)?;
        let pub_k = pk.public_key(&secp);

        let account = pub_k.account(prefix)?;
        assert_eq!(&account, "terra1jnzv225hwl3uxc5wtnlgr8mwy6nlt0vztv3qqm");
        assert_eq!(
            &pub_k.operator_address_public_key(prefix)?,
            "terravaloperpub1addwnpepqt8ha594svjn3nvfk4ggfn5n8xd3sm3cz6ztxyugwcuqzsuuhhfq5y7accr"
        );
        assert_eq!(
            &pub_k.application_public_key(prefix)?,
            "terrapub1addwnpepqt8ha594svjn3nvfk4ggfn5n8xd3sm3cz6ztxyugwcuqzsuuhhfq5nwzrf9"
        );

        Ok(())
    }
    // #[test]
    // pub fn test_sign() -> anyhow::Result<()> {
    //     // This test is using message from python SDK.. so these keys generate same sigs as they do.
    //     let str_1 =  "island relax shop such yellow opinion find know caught erode blue dolphin behind coach tattoo light focus snake common size analyst imitate employ walnut";
    //     let coin_type: u32 = 330;
    //     let secp = Secp256k1::new();
    //     let pk = PrivateKey::from_words(&secp, str_1, 0, 0, coin_type)?;
    //     let _pub_k = pk.public_key(&secp);
    //     let to_sign = r#"{"account_number":"45","chain_id":"columbus-3-testnet","fee":{"amount":[{"amount":"698","denom":"uluna"}],"gas":"46467"},"memo":"","msgs":[{"type":"bank/MsgSend","value":{"amount":[{"amount":"100000000","denom":"uluna"}],"from_address":"terra1n3g37dsdlv7ryqftlkef8mhgqj4ny7p8v78lg7","to_address":"terra1wg2mlrxdmnnkkykgqg4znky86nyrtc45q336yv"}}],"sequence":"0"}"#;

    //     let sig = pk.sign(&secp, to_sign)?;

    //     assert_eq!(
    //         sig.pub_key.value,
    //         "AiMzHaA2bvnDXfHzkjMM+vkSE/p0ymBtAFKUnUtQAeXe"
    //     );
    //     assert_eq!(sig.signature, "FJKAXRxNB5ruqukhVqZf3S/muZEUmZD10fVmWycdVIxVWiCXXFsUy2VY2jINEOUGNwfrqEZsT2dUfAvWj8obLg==");

    //     Ok(())
    // }
}
