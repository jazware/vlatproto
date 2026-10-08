//! atproto as vlpds and vlRelay both speak it: the repo data model
//! ([`cbor`], [`cid`], [`tid`], [`car`], [`car_order`], [`mst`]), K-256
//! keys ([`crypto`]), firehose frames, built ([`events`]) and read
//! ([`frame`]), PLC operations ([`plc`]), identifier syntax ([`syntax`]),
//! DID resolution ([`did_resolver`]) over the shared outbound clients
//! ([`http`]), and XRPC errors ([`xrpc`]).
#![allow(clippy::type_complexity)]

/// `lazy!(NAME: Type = register_...!(...))`: a metric in prometheus's
/// default registry (the one a server's /metrics gathers), registered on
/// first use.
macro_rules! lazy {
    ($name:ident: $t:ty = $e:expr) => {
        pub static $name: ::std::sync::LazyLock<$t> = ::std::sync::LazyLock::new(|| $e.unwrap());
    };
}
pub(crate) use lazy;

pub mod car;
pub mod car_order;
pub mod cbor;
pub mod cid;
pub mod crypto;
pub mod did_resolver;
pub mod events;
pub mod frame;
pub mod http;
pub mod mst;
pub mod plc;
pub mod syntax;
pub mod tid;
pub mod xrpc;
