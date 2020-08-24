use crate::database::{BatchDatabase, Database, MemoryDatabase};
use crate::{blockchain, descriptor, error, Wallet};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey, PrivateKey};
use bitcoin::{secp256k1, Network};
use rand::{thread_rng, RngCore};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct WalletDesriptors {
    network: bitcoin::Network,
    external: String,
    internal: String,
    public: String,
}
pub struct WalletOptions {
    name: String,
    descriptors: WalletDesriptors,
}
//fn prepare_home_dir(db_path: String) -> PathBuf {
//    let mut dir = PathBuf::new();
//    dir.push(PathBuf::from_str(&db_path).unwrap());
//    // dir.push(&dirs::home_dir().unwrap());
//    dir.push(".magical-bitcoin");

//    if !dir.exists() {
//        println!("Creating home directory {}", dir.as_path().display());
//        fs::create_dir(&dir).unwrap();
//    }

//    dir.push("database.sled");
//    dir
//}
//fn load_wallet(db_type: DatabaseOption, wallet: WalletOptions) -> Box<dyn BatchDatabase> {
//    let db = match db_type {
//        DatabaseOption::Sled(x) => {
//            let database = sled::open(prepare_home_dir(x.dir).to_str().unwrap()).unwrap();
//            let tree = database.open_tree(wallet.wallet_name).unwrap();
//            println!("database opened successfully");
//            database
//        }
//        DatabaseOption::Memory => {
//            let database = MemoryDatabase::new();
//            database
//        }
//    };
//    Box::new(db)
//}

pub mod api {
    use super::*;
    pub fn generate_extended_priv_key(network: bitcoin::Network) -> ExtendedPrivKey {
        let mut entropy = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
        thread_rng().fill_bytes(&mut entropy);
        let key = ExtendedPrivKey::new_master(network, &entropy);
        key.unwrap()
    }
    pub fn generate_wif(network: Network) -> String {
        let mut entropy = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
        thread_rng().fill_bytes(&mut entropy);
        bitcoin::PrivateKey {
            compressed: true,
            network,
            key: secp256k1::SecretKey::from_slice(&entropy).expect("Error passing"),
        }
        .to_wif()
    }
    /// Generates basic P2PKH wallet internal, external descriptor
    pub fn generate_wallet_descriptors(
        network: bitcoin::Network,
    ) -> Result<WalletDesriptors, descriptor::error::Error> {
        // let descriptor = format!("pkh({})", generate_wif(network));
        let extended_priv_key = generate_extended_priv_key(network);
        //  m/0
        let wallet = extended_priv_key.ckd_priv(
            &bitcoin::secp256k1::Secp256k1::new(),
            ChildNumber::Hardened { index: 0 },
        )?;
        // m/0'/0'
        let wallet_chain_int = wallet.ckd_priv(
            &secp256k1::Secp256k1::new(),
            ChildNumber::Hardened { index: 0 },
        )?;
        // m/0'/1'
        let wallet_chain_ext = wallet.ckd_priv(
            &secp256k1::Secp256k1::new(),
            ChildNumber::Hardened { index: 1 },
        )?;

        let wallet_chain_ext_pubkey =
            ExtendedPubKey::from_private(&secp256k1::Secp256k1::new(), &wallet_chain_ext);

        println!(
        "Generated a new wallet!\nXprv:{:?}\ndepth:{:?}\nchild number:{:?}.\nHaving Xpub:{:?}\n\n",
        wallet_chain_ext.to_string(),
        wallet_chain_ext.depth,
        wallet_chain_ext.child_number,
        wallet_chain_ext_pubkey.to_string(),
    );
        //
        let descriptor_ext = format!(
            "pkh({}/{}/*')",
            wallet_chain_ext.to_string(),
            format!("{}/", wallet_chain_ext.child_number.to_string())
                .repeat(wallet_chain_ext.depth.into())
                .trim_end_matches("/"),
        );

        let descriptor_int = format!(
            "pkh({}/{}/*')",
            wallet_chain_int.to_string(),
            format!("{}/", wallet_chain_int.child_number.to_string())
                .repeat(wallet_chain_int.depth.into())
                .trim_end_matches("/"),
        );
        let descriptor_ext_xpub = format!(
            "pkh([{}/44'/{}/{}']{}/{}/*')",
            // "pkh([{}/44'/{}/{}']{}/{}/{}/*')",
            wallet_chain_ext_pubkey.parent_fingerprint,
            wallet.child_number,
            wallet_chain_ext_pubkey.child_number,
            wallet_chain_ext_pubkey.to_string(),
            // wallet.child_number,
            wallet_chain_ext.child_number
        );
        Ok(WalletDesriptors {
            network,
            external: descriptor_ext,
            internal: descriptor_int,
            public: descriptor_ext_xpub,
        })
    }
    fn prepare_wallet(
        wallet: &WalletOptions,
    ) -> Result<Wallet<blockchain::EsploraBlockchain, MemoryDatabase>, error::Error> {
        #[cfg(feature = "esplora")]
        let blockchain_source =
            blockchain::EsploraBlockchain::new(&"https://blockstream.info".to_string());
        Wallet::new(
            &wallet.descriptors.external,
            Some(&wallet.descriptors.internal),
            // Some(&change_descriptor),
            wallet.descriptors.network,
            MemoryDatabase::new(),
            blockchain_source,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prv_and_pub_descriptor_derive_same_results() {
        let desc = api::generate_wallet_descriptors(Network::Testnet).unwrap();
        let extended_desc_ext = descriptor::ExtendedDescriptor::from_str(&desc.external).unwrap();
        let extended_desc_ext_pub = descriptor::ExtendedDescriptor::from_str(&desc.public).unwrap();

        // test xpub and xprv descriptors generate same addresses
        [1, 42, 23323]
            .iter()
            .map(|x| {
                let xprv_derived = extended_desc_ext
                    .derive(*x)
                    .unwrap()
                    .address(desc.network)
                    .unwrap()
                    .to_string();
                let tpub_devrived = extended_desc_ext_pub
                    .derive(*x)
                    .unwrap()
                    .address(desc.network)
                    .unwrap()
                    .to_string();
                println!("{} {}", xprv_derived, tpub_devrived);
                assert_eq!(xprv_derived, tpub_devrived);
            })
            .for_each(drop);
    }
}
