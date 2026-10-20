use std::net::{IpAddr, SocketAddr};

use http::Request;
use tonic::Request as TonicRequest;
use tonic::transport::server::TcpConnectInfo;

const CLIENT_IP_METADATA: &str = "x-lore-client-ip";

pub(crate) fn peer_ip_from_request<B>(request: &Request<B>) -> Option<IpAddr> {
    request
        .extensions()
        .get::<TcpConnectInfo>()
        .and_then(TcpConnectInfo::remote_addr)
        .map(|addr| normalize_ip(addr.ip()))
}

pub(crate) fn peer_key_from_request<B>(request: &Request<B>) -> String {
    peer_ip_from_request(request)
        .map(|addr| addr.to_string())
        .unwrap_or_default()
}

pub(crate) fn client_ip_from_grpc_request<T>(request: &TonicRequest<T>) -> Option<IpAddr> {
    let peer_ip = request
        .extensions()
        .get::<TcpConnectInfo>()
        .and_then(TcpConnectInfo::remote_addr)
        .map(|addr| normalize_ip(addr.ip()))?;
    let forwarded_ip = request
        .metadata()
        .get(CLIENT_IP_METADATA)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<IpAddr>().ok());
    client_ip_from_peer(peer_ip, forwarded_ip)
}

fn client_ip_from_peer(peer_ip: IpAddr, forwarded_ip: Option<IpAddr>) -> Option<IpAddr> {
    if peer_ip.is_loopback() {
        forwarded_ip.map(normalize_ip)
    } else {
        Some(peer_ip)
    }
}

fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
    }
}

#[allow(dead_code)]
pub(crate) fn normalize_socket_addr(addr: SocketAddr) -> IpAddr {
    normalize_ip(addr.ip())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::client_ip_from_peer;

    #[test]
    fn loopback_proxy_requires_forwarded_client_ip() {
        assert_eq!(
            client_ip_from_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), None),
            None
        );
        assert_eq!(
            client_ip_from_peer(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some("192.0.2.99".parse().expect("parse client IP"))
            ),
            Some("192.0.2.99".parse().expect("parse client IP"))
        );
    }

    #[test]
    fn external_peer_cannot_spoof_forwarded_client_ip() {
        assert_eq!(
            client_ip_from_peer(
                "198.51.100.99".parse().expect("parse peer IP"),
                Some("192.0.2.99".parse().expect("parse forwarded IP"))
            ),
            Some("198.51.100.99".parse().expect("parse peer IP"))
        );
    }
}
