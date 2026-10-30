//! English admin UI text and template key integrity checks.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

const EN_DICT_RAW: &str = include_str!("i18n/en.yaml");
const BASE_TEMPLATE_RAW: &str = include_str!("../../templates/admin/base.html");
const DASHBOARD_TEMPLATE_RAW: &str = include_str!("../../templates/admin/dashboard.html");
const REPOSITORIES_TEMPLATE_RAW: &str = include_str!("../../templates/admin/repositories.html");
const REPOSITORIES_TABLE_TEMPLATE_RAW: &str =
    include_str!("../../templates/admin/repositories_table.html");
const USERS_TEMPLATE_RAW: &str = include_str!("../../templates/admin/users.html");
const USERS_TABLE_TEMPLATE_RAW: &str = include_str!("../../templates/admin/users_table.html");
const USER_ACCESS_TEMPLATE_RAW: &str = include_str!("../../templates/admin/user_access.html");
const SERVER_SETTINGS_TEMPLATE_RAW: &str =
    include_str!("../../templates/admin/server_settings.html");
const SERVICE_ACCOUNT_CREATED_TEMPLATE_RAW: &str =
    include_str!("../../templates/admin/service_account_created.html");
const GROUPS_TEMPLATE_RAW: &str = include_str!("../../templates/admin/groups.html");
const GROUP_ACCESS_TEMPLATE_RAW: &str = include_str!("../../templates/admin/group_access.html");
const SIMULATOR_TEMPLATE_RAW: &str = include_str!("../../templates/admin/simulator.html");

static EN_DICT: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| load_dictionary("en", EN_DICT_RAW));
pub(super) fn translate(key: &str) -> String {
    EN_DICT.get(key).cloned().unwrap_or_else(|| key.to_owned())
}

fn load_dictionary(lang: &str, raw: &str) -> BTreeMap<String, String> {
    serde_yaml_ng::from_str(raw).unwrap_or_else(|err| panic!("admin {lang} i18n failed: {err}"))
}

pub fn assert_i18n_integrity() {
    let en_keys = EN_DICT.keys().cloned().collect::<BTreeSet<_>>();
    let template_keys = template_i18n_keys();
    assert!(
        !template_keys.is_empty(),
        "admin templates must reference i18n keys"
    );
    for key in template_keys {
        assert!(en_keys.contains(&key), "missing admin i18n key {key:?}");
    }
}

fn template_i18n_keys() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for source in [
        BASE_TEMPLATE_RAW,
        DASHBOARD_TEMPLATE_RAW,
        REPOSITORIES_TEMPLATE_RAW,
        REPOSITORIES_TABLE_TEMPLATE_RAW,
        USERS_TEMPLATE_RAW,
        USERS_TABLE_TEMPLATE_RAW,
        USER_ACCESS_TEMPLATE_RAW,
        SERVER_SETTINGS_TEMPLATE_RAW,
        SERVICE_ACCOUNT_CREATED_TEMPLATE_RAW,
        GROUPS_TEMPLATE_RAW,
        GROUP_ACCESS_TEMPLATE_RAW,
        SIMULATOR_TEMPLATE_RAW,
    ] {
        let mut rest = source;
        while let Some((_, tail)) = rest.split_once("t(\"") {
            if let Some((key, after)) = tail.split_once("\")") {
                out.insert(key.to_owned());
                rest = after;
            } else {
                break;
            }
        }
    }
    out
}
