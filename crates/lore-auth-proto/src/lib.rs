//! Generated Rust bindings for the Lore repository, UCS Auth, and ReBAC gRPC protocols.
//!
//! This crate owns tonic/prost code generation from `third_party/lore-proto`.
//! Runtime code should depend on these modules instead of hand-written protocol
//! structs.

pub mod epic_urc {
    //! `epic_urc.UrcAuthApi` messages and tonic client/server types.

    tonic::include_proto!("epic_urc");
}

pub mod ucs {
    //! `ucs.*` protocol namespaces.

    pub mod auth {
        //! `ucs.auth.RebacApi` messages and tonic client/server types.

        tonic::include_proto!("ucs.auth");
    }
}

pub mod lore {
    pub mod repository {
        pub mod v1 {
            tonic::include_proto!("lore.repository.v1");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn generated_server_traits_are_available() {
        let trait_names = [
            core::any::type_name::<&dyn crate::epic_urc::urc_auth_api_server::UrcAuthApi>(),
            core::any::type_name::<&dyn crate::ucs::auth::rebac_api_server::RebacApi>(),
        ];

        assert!(trait_names[0].contains("UrcAuthApi"));
        assert!(trait_names[1].contains("RebacApi"));
    }
}
