use crate::sentry::{
    devp2p::{disc::dns::Resolver, *},
    DnsDiscovery, StaticNodes,
};
use anyhow::format_err;
use derive_more::FromStr;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::info;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, FromStr)]
pub struct NR(pub NodeRecord);

#[derive(Debug, FromStr)]
pub struct Discv4NR(pub crate::sentry::devp2p::disc::v4::NodeRecord);

pub struct OptsDnsDisc {
    pub address: String,
}

impl OptsDnsDisc {
    pub fn make_task(self) -> anyhow::Result<DnsDiscovery> {
        info!("Starting DNS discovery fetch from {}", self.address);

        let dns_resolver = Resolver::new(Arc::new(
            TokioAsyncResolver::tokio_from_system_conf()
                .map_err(|err| format_err!("Failed to start DNS resolver: {err}"))?,
        ));

        let task = DnsDiscovery::new(Arc::new(dns_resolver), self.address, None);

        Ok(task)
    }
}

pub struct OptsDiscStatic {
    pub static_peers: Vec<NR>,
    pub static_peers_interval: u64,
}

impl OptsDiscStatic {
    pub fn make_task(self) -> anyhow::Result<StaticNodes> {
        info!("Enabling static peers: {:?}", self.static_peers);

        let task = StaticNodes::new(
            self.static_peers
                .iter()
                .map(|&NR(NodeRecord { addr, id })| (addr, id))
                .collect::<HashMap<_, _>>(),
            Duration::from_millis(self.static_peers_interval),
        );
        Ok(task)
    }
}
