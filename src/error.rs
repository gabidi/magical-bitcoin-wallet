use std::fmt;

use bitcoin::{Address, OutPoint};

#[derive(Debug)]
pub enum Error {
    KeyMismatch(bitcoin::secp256k1::PublicKey, bitcoin::secp256k1::PublicKey),
    MissingInputUTXO(usize),
    InvalidU32Bytes(Vec<u8>),
    Generic(String),
    ScriptDoesntHaveAddressForm,
    SendAllMultipleOutputs,
    NoAddressees,
    OutputBelowDustLimit(usize),
    InsufficientFunds,
    InvalidAddressNetwork(Address),
    UnknownUTXO,
    DifferentTransactions,
    TransactionNotFound,
    TransactionConfirmed,
    IrreplaceableTransaction,
    FeeRateTooLow(crate::wallet::utils::FeeRate),

    ChecksumMismatch,
    DifferentDescriptorStructure,

    SpendingPolicyRequired,
    InvalidPolicyPathError(crate::descriptor::policy::PolicyError),

    Signer(crate::wallet::signer::SignerError),

    // Blockchain interface errors
    Uncapable(crate::blockchain::Capability),
    OfflineClient,
    InvalidProgressValue(f32),
    ProgressUpdateError,
    MissingCachedAddresses,
    InvalidOutpoint(OutPoint),

    Descriptor(crate::descriptor::error::Error),
    AddressValidator(crate::wallet::address_validator::AddressValidatorError),

    Encode(bitcoin::consensus::encode::Error),
    Miniscript(miniscript::Error),
    BIP32(bitcoin::util::bip32::Error),
    Secp256k1(bitcoin::secp256k1::Error),
    JSON(serde_json::Error),
    Hex(bitcoin::hashes::hex::Error),
    PSBT(bitcoin::util::psbt::Error),

    #[cfg(feature = "electrum")]
    Electrum(electrum_client::Error),
    #[cfg(feature = "esplora")]
    Esplora(crate::blockchain::esplora::EsploraError),
    #[cfg(feature = "compact_filters")]
    CompactFilters(crate::blockchain::compact_filters::CompactFiltersError),
    #[cfg(feature = "key-value-db")]
    Sled(sled::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

macro_rules! impl_error {
    ( $from:ty, $to:ident ) => {
        impl std::convert::From<$from> for Error {
            fn from(err: $from) -> Self {
                Error::$to(err)
            }
        }
    };
}

impl_error!(crate::descriptor::error::Error, Descriptor);
impl_error!(
    crate::wallet::address_validator::AddressValidatorError,
    AddressValidator
);
impl_error!(
    crate::descriptor::policy::PolicyError,
    InvalidPolicyPathError
);
impl_error!(crate::wallet::signer::SignerError, Signer);

impl_error!(bitcoin::consensus::encode::Error, Encode);
impl_error!(miniscript::Error, Miniscript);
impl_error!(bitcoin::util::bip32::Error, BIP32);
impl_error!(bitcoin::secp256k1::Error, Secp256k1);
impl_error!(serde_json::Error, JSON);
impl_error!(bitcoin::hashes::hex::Error, Hex);
impl_error!(bitcoin::util::psbt::Error, PSBT);

#[cfg(feature = "electrum")]
impl_error!(electrum_client::Error, Electrum);
#[cfg(feature = "esplora")]
impl_error!(crate::blockchain::esplora::EsploraError, Esplora);
#[cfg(feature = "key-value-db")]
impl_error!(sled::Error, Sled);

#[cfg(feature = "compact_filters")]
impl From<crate::blockchain::compact_filters::CompactFiltersError> for Error {
    fn from(other: crate::blockchain::compact_filters::CompactFiltersError) -> Self {
        match other {
            crate::blockchain::compact_filters::CompactFiltersError::Global(e) => *e,
            err @ _ => Error::CompactFilters(err),
        }
    }
}
