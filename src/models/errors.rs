use super::*;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum NotFound {
    NodeConfig,
    Body { number: BlockNumber, hash: H256 },
    Header { number: BlockNumber, hash: H256 },
    CanonicalHash { number: BlockNumber },
    Account { address: Address },
}

impl Display for NotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} not found",
            match self {
                Self::NodeConfig => "node config".into(),
                Self::Body { number, hash } => format!("body (#{number}/{hash:?})"),
                Self::Header { number, hash } => format!("header (#{number}/{hash:?})"),
                Self::CanonicalHash { number } => format!("canonical hash for block #{number}"),
                Self::Account { address } => format!("account {address}"),
            }
        )
    }
}

impl std::error::Error for NotFound {}
