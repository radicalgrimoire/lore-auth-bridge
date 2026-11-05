use std::net::IpAddr;

use ipnet::IpNet;

use crate::{CoreError, ports::GroupQuery};

pub async fn require_allowed_ip(
    groups: &dyn GroupQuery,
    user_id: &str,
    client_ip: Option<IpAddr>,
    require_cidr: bool,
) -> Result<(), CoreError> {
    let cidrs = groups.list_user_allowed_cidrs(user_id).await?;
    if cidrs.is_empty() {
        return if require_cidr {
            Err(CoreError::PermissionDenied)
        } else {
            Ok(())
        };
    }
    let client_ip = client_ip.ok_or(CoreError::PermissionDenied)?;
    let mut allowed = false;
    for cidr in cidrs {
        let network = cidr
            .parse::<IpNet>()
            .map_err(|_| CoreError::InvalidArgument("stored group CIDR is invalid".to_owned()))?;
        allowed |= network.contains(&client_ip);
    }
    if allowed {
        Ok(())
    } else {
        Err(CoreError::PermissionDenied)
    }
}
