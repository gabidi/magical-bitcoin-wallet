use crate::database::{BatchDatabase, BatchOperations, Database, MemoryDatabase};
use crate::{blockchain, descriptor, error, Wallet};
use bitcoin::util::bip32::{ChildNumber, Error as Bip32Error, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{secp256k1, Network};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

pub enum WalletDb {
    MemoryDatabase(MemoryDatabase),
    Sled(sled::Tree),
}
impl From<WalletDb> for MemoryDatabase {
    fn from(item: WalletDb) -> MemoryDatabase {
        if let WalletDb::MemoryDatabase(x) = item {
            x
        } else {
            panic!("WTF!!");
        }
    }
}
impl From<WalletDb> for sled::Tree {
    fn from(item: WalletDb) -> sled::Tree {
        if let WalletDb::Sled(x) = item {
            x
        } else {
            panic!("WTF!! 2");
        }
    }
}
pub mod api {
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
    fn prepare_db_path(db_path: String) -> PathBuf {
        let mut dir = prepare_path(db_path);
        dir.push("database.sled");
        dir
    }
    fn load_wallet_db(wallet_db_cfg: &WalletDbCfg) -> WalletDb {
        match &wallet_db_cfg.db_type {
            WalletDbCfgTypes::Sled { path, name } => {
                let database =
                    sled::open(prepare_db_path(path.to_string()).to_str().unwrap()).unwrap();
                WalletDb::Sled(database.open_tree(name).unwrap())
            }
            WalletDbCfgTypes::MemoryDatabase => WalletDb::MemoryDatabase(MemoryDatabase::new()),
        }
    }

    pub fn prepare_wallet_from_json(
        wallet_json: &String,
    ) -> Result<Wallet<blockchain::EsploraBlockchain, MemoryDatabase>, error::Error> {
        let wallet_cfg: WalletCfg = serde_json::from_str(&wallet_json).unwrap();
        // FIXME as cfg
        let blockchain_source =
            blockchain::EsploraBlockchain::new(&"https://blockstream.info".to_string());
        let mut wallet_db = load_wallet_db(&wallet_cfg.db_cfg);

        Wallet::new(
            &wallet_cfg.descriptors.external,
            Some(&wallet_cfg.descriptors.internal),
            wallet_cfg.descriptors.network,
            wallet_db.into(),
            blockchain_source,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn should_generate_valid_external_tpub_tprv_descriptors() {
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
                assert_eq!(xprv_derived, tpub_devrived);
            })
            .for_each(drop);
    }

    #[test]
    fn should_instantiate_wallet_from_json_cfg() {
        // TODO this is the setup with user input process
        // once done this is saved in App space as PGP encrypted ?
        let descriptors = api::generate_wallet_descriptors(Network::Testnet).unwrap();
        let wallet_options = WalletCfg {
            name: "test".to_string(),
            descriptors,
            address_look_ahead: 20,
            db_cfg: WalletDbCfg {
                db_type: WalletDbCfgTypes::MemoryDatabase,
            },
        };
        // address to test get address
        let address_ext =
            descriptor::ExtendedDescriptor::from_str(&wallet_options.descriptors.external)
                .unwrap()
                .derive(0)
                .unwrap()
                .address(bitcoin::Network::Testnet)
                .unwrap()
                .to_string();

        // Serialize wallet CFG into JSON string
        let serialized = serde_json::to_string(&wallet_options).unwrap();

        let wallet = api::prepare_wallet_from_json(&serialized).unwrap();
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
    //    //api::spendRequest(WithdrawToAddressRequest {... });
    //}
}
