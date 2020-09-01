use crate::database::{BatchDatabase, BatchOperations, Database, MemoryDatabase};
use crate::{blockchain, descriptor, error, Client, Wallet};
use bitcoin::util::bip32::{ChildNumber, Error as Bip32Error, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{secp256k1, Network};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletDescriptors {
    network: bitcoin::Network,
    external: String,
    internal: String,
    public: String,
}
#[derive(Serialize, Deserialize)]
pub enum WalletDbCfgTypes {
    Sled { path: String, name: String },
    MemoryDatabase,
}
#[derive(Serialize, Deserialize)]
pub struct WalletDbCfg {
    db_type: WalletDbCfgTypes,
}
#[derive(Serialize, Deserialize)]
pub struct WalletCfg {
    name: String,
    descriptors: WalletDescriptors,
    address_look_ahead: u32,
    db_cfg: WalletDbCfg,
    chain_cfg: WalletBlockchainCfg,
}
#[derive(Serialize, Deserialize)]
pub enum WalletBlockchainCfg {
    Esplora {
        url: String,
    },
    Electrum {
        server: String,
        proxy: Option<String>,
    },
    BitcoinCoreRpc {
        onion_url: String,
    },
}
//impl<I: blockchain::Blockchain> From<WalletBlockchainCfg> for I {
//    fn from(item: WalletBlockchainCfg) -> I {
//        if let WalletBlockchainCfg::Esplora { url } = item {
//            blockchain::EsploraBlockchain::new(&url.to_string())
//        } else if let WalletBlockchainCfg::Electrum { server, proxy } = item {
//            // TODO replace None with proxy
//            let client = Client::new(&server, None).unwrap();
//            blockchain::ElectrumBlockchain::from(client)
//        } else {
//            panic!(
//                "Can only convert Esplora variant of WalletBlockchainCfg into EsploraBlockchain"
//            );
//        }
//    }
//}

#[cfg(feature = "esplora")]
impl From<WalletBlockchainCfg> for blockchain::EsploraBlockchain {
    fn from(item: WalletBlockchainCfg) -> blockchain::EsploraBlockchain {
        if let WalletBlockchainCfg::Esplora { url } = item {
            blockchain::EsploraBlockchain::new(&url.to_string())
        } else {
            panic!(
                "Can only convert Esplora variant of WalletBlockchainCfg into EsploraBlockchain"
            );
        }
    }
}
impl From<WalletBlockchainCfg> for blockchain::ElectrumBlockchain {
    fn from(item: WalletBlockchainCfg) -> blockchain::ElectrumBlockchain {
        if let WalletBlockchainCfg::Electrum { server, proxy } = item {
            // TODO replace None with proxy
            let client = Client::new(&server, None).unwrap();
            blockchain::ElectrumBlockchain::from(client)
        } else {
            panic!(
                "Can only convert Esplora variant of WalletBlockchainCfg into EsploraBlockchain"
            );
        }
    }
}

impl From<WalletDbCfgTypes> for MemoryDatabase {
    fn from(item: WalletDbCfgTypes) -> MemoryDatabase {
        if let WalletDbCfgTypes::MemoryDatabase = item {
            MemoryDatabase::new()
        } else {
            panic!("Can only convert MemoryDatabase variant of WalletDb into MemoryDatabase");
        }
    }
}
impl From<WalletDbCfgTypes> for sled::Tree {
    fn from(item: WalletDbCfgTypes) -> sled::Tree {
        if let WalletDbCfgTypes::Sled { path, name } = item {
            let database = sled::open(wallet_api::prepare_db_path(path).to_str().unwrap()).unwrap();
            database.open_tree(name).unwrap()
        } else {
            panic!("Can only convert MemoryDatabase variant of WalletDb into MemoryDatabase");
        }
    }
}
pub mod wallet_api {
    use super::*;
    pub fn generate_extended_priv_key(
        network: bitcoin::Network,
    ) -> Result<ExtendedPrivKey, Bip32Error> {
        let mut entropy = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
        thread_rng().fill_bytes(&mut entropy);
        ExtendedPrivKey::new_master(network, &entropy)
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
    // FIXME refactor this to generate_pkh_descriptors_from_extended_priv
    // FIXME refactor this to generate_multisign_descriptors_from_extended_priv
    pub fn generate_wallet_descriptors(
        network: bitcoin::Network,
    ) -> Result<WalletDescriptors, descriptor::error::Error> {
        // let descriptor = format!("pkh({})", generate_wif(network));
        let extended_priv_key = generate_extended_priv_key(network)?;
        //  m/0
        let wallet = extended_priv_key.ckd_priv(
            &bitcoin::secp256k1::Secp256k1::new(),
            ChildNumber::Hardened { index: 0 },
        )?;
        // m/0'/0'
        let wallet_chain_int = wallet.ckd_priv(
            &secp256k1::Secp256k1::new(),
            ChildNumber::Hardened { index: 1 },
        )?;
        // m/0'/1'
        let wallet_chain_ext = wallet.ckd_priv(
            &secp256k1::Secp256k1::new(),
            ChildNumber::Hardened { index: 0 },
        )?;

        let wallet_chain_ext_pubkey =
            ExtendedPubKey::from_private(&secp256k1::Secp256k1::new(), &wallet_chain_ext);

        let descriptor_int = format!(
            "pkh({}/{}/*)",
            wallet_chain_int.to_string(),
            wallet_chain_int
                .child_number
                .to_string()
                .trim_end_matches("'")
        );
        let descriptor_ext = format!(
            "pkh({}/{}/*)",
            wallet_chain_ext.to_string(),
            wallet_chain_ext
                .child_number
                .to_string()
                .trim_end_matches("'")
        );
        let descriptor_ext_xpub = format!(
            "pkh([{}/44'/{}/{}]{}/{}/*)",
            wallet_chain_ext_pubkey.parent_fingerprint,
            wallet.child_number,
            wallet_chain_ext_pubkey.child_number,
            wallet_chain_ext_pubkey.to_string(),
            wallet_chain_ext
                .child_number
                .to_string()
                .trim_end_matches("'")
        );
        Ok(WalletDescriptors {
            network,
            external: descriptor_ext,
            internal: descriptor_int,
            public: descriptor_ext_xpub,
        })
    }
    fn prepare_path(db_path: String) -> PathBuf {
        let mut dir = PathBuf::new();
        dir.push(PathBuf::from_str(&db_path).unwrap());
        dir.push(".sifir-magical-bitcoin");
        if !dir.exists() {
            println!("Creating db directory {}", dir.as_path().display());
            fs::create_dir(&dir).unwrap();
        }
        dir
    }

    // FIXME put all wallet loading fns in a struct
    pub fn prepare_db_path(db_path: String) -> PathBuf {
        let mut dir = prepare_path(db_path);
        dir.push("database.sled");
        dir
    }
    pub fn prepare_wallet_from_json(
        wallet_json: &String,
        // FIXME return types for this funtion ?  into works because rust infer return types from
        // sig.. maybe something in the function sig call ?
    ) -> Result<Wallet<blockchain::ElectrumBlockchain, MemoryDatabase>, error::Error> {
        let wallet_cfg: WalletCfg = serde_json::from_str(&wallet_json).unwrap();
        Wallet::new(
            &wallet_cfg.descriptors.external,
            Some(&wallet_cfg.descriptors.internal),
            wallet_cfg.descriptors.network,
            wallet_cfg.db_cfg.db_type.into(),
            wallet_cfg.chain_cfg.into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn should_parse_valid_tprv() {
        let tprv =  "pkh(tprv8eHfgaBJ1oag7FF1hnTUSWEnbhscsktkAcvpLBRMbitEhw1uDjp5ztLFd2ajFjS4Scc6CZc94aLD6QxTeq7z61iWtX91FmdZrWcWnPkniYP/0/*)";
        descriptor::ExtendedDescriptor::from_str(tprv).unwrap();
    }
    #[test]
    fn should_generate_valid_external_tpub_tprv_descriptors() {
        let desc = wallet_api::generate_wallet_descriptors(Network::Testnet).unwrap();
        println!("{:?}", desc);
        let extended_desc_ext = descriptor::ExtendedDescriptor::from_str(&desc.external).unwrap();
        let extended_desc_ext_pub = descriptor::ExtendedDescriptor::from_str(&desc.public).unwrap();

        // test xpub and xprv descriptors generate same addresses
        [1, 42, 23323]
            .iter()
            .map(|x| {
                let xprv_derived = extended_desc_ext
                    .derive(&[ChildNumber::from_normal_idx(*x).unwrap()])
                    .address(desc.network)
                    .unwrap()
                    .to_string();
                let tpub_devrived = extended_desc_ext_pub
                    .derive(&[ChildNumber::from_normal_idx(*x).unwrap()])
                    .address(desc.network)
                    .unwrap()
                    .to_string();
                assert_eq!(
                    xprv_derived, tpub_devrived,
                    "Prv address equals tpub address"
                );
            })
            .for_each(drop);
    }

    #[test]
    fn should_instantiate_wallet_from_json_cfg() {
        // TODO this is the setup with user input process
        // once done this is saved in App space as PGP encrypted ?
        let descriptors = wallet_api::generate_wallet_descriptors(Network::Testnet).unwrap();
        let wallet_options = WalletCfg {
            name: "test".to_string(),
            descriptors,
            address_look_ahead: 20,
            db_cfg: WalletDbCfg {
                db_type: WalletDbCfgTypes::MemoryDatabase,
            },
            chain_cfg: WalletBlockchainCfg::Esplora {
                url: "https://blockstream.info".to_string(),
            },
        };
        // address to test get address
        let address_ext =
            descriptor::ExtendedDescriptor::from_str(&wallet_options.descriptors.external)
                .unwrap()
                .derive(&[ChildNumber::from_normal_idx(0).unwrap()])
                .address(bitcoin::Network::Testnet)
                .unwrap()
                .to_string();

        // Serialize wallet CFG into JSON string
        let serialized = serde_json::to_string(&wallet_options).unwrap();

        let wallet = wallet_api::prepare_wallet_from_json(&serialized).unwrap();
        // FIXME enabling sync will reuslt in incorrect adddres compare. What index does sync leave
        // dervie at ?
        // wallet.sync(Some(wallet_options.address_look_ahead));

        assert_eq!(wallet.get_balance().unwrap(), 0);
        assert_eq!(wallet.get_new_address().unwrap().to_string(), address_ext);
    }
    // TODO simplfy withdraw request a la BDK RN native wrapre
    //struct WithdrawToAddressRequest {
    //    address: String,
    //    fee: Option<i32>,
    //    amount: i32,
    //}
    //impl WithdrawToAddressRequest{
    //    fn new(address:String,amount:i64 ,fee:Option<fee:String>)->WithdrawToAddressRequest{
    //        WithdrawToAddressRequest{
    //          // FIXME needed ?
    //        }
    //    };
    //    fn get_address(&self){
    //
    //    };
    //}
    //#[test]

    //fn should_withdraw_to_adddres() {
    //    //wallet_api::spendRequest(WithdrawToAddressRequest {... });
    //}
}
