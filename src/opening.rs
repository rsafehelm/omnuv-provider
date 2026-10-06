//! **The provider opening**: moved to `onv_hostnet::opening` with no
//! behaviour change (omnuv's modular design, work package A1b). The one test
//! that holds it against join's copy of the egress subnet stays here, beside
//! join.

pub(crate) use onv_hostnet::opening::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn the_egress_subnet_is_the_one_join_and_the_play_create() {
        assert!(in_egress(Ipv4Addr::new(10, 201, 0, 100)) && in_egress(Ipv4Addr::new(10, 201, 0, 250)));
        assert!(!in_egress(Ipv4Addr::new(10, 201, 1, 1)) && !in_egress(Ipv4Addr::new(192, 168, 100, 78)));
        assert_eq!(format!("{}/{}", EGRESS_NET.0, EGRESS_NET.1), crate::join::EGRESS_SUBNET);
    }
}
