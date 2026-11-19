use std::net::SocketAddr;
use std::path::PathBuf;

pub const RESOLVERS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.10",
    "149.112.112.10",
    "94.140.14.140",
    "94.140.14.141",
    "208.67.222.222",
    "208.67.220.220",
];

pub const KNOWN_LISTS: &[&str] = &[
    "light",
    "multi",
    "pro",
    "pro.plus",
    "ultimate",
    "native.amazon",
    "native.apple",
    "native.huawei",
    "native.lgwebos",
    "native.oppo-realme",
    "native.roku",
    "native.samsung",
    "native.tiktok",
    "native.tiktok.extended",
    "native.vivo",
    "native.winoffice",
    "native.xiaomi",
];

pub const KNOWN_LIST_URL: &str =
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/";
pub const PSL_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";
pub const USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";

pub fn resolvers() -> Vec<SocketAddr> {
    RESOLVERS
        .iter()
        .filter_map(|r| format!("{r}:53").parse().ok())
        .collect()
}

#[derive(Clone)]
pub struct Paths {
    pub state: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        let state = std::env::var_os("STELLA_STATE")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("XDG_STATE_HOME").map(|d| PathBuf::from(d).join("stella")))
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state/stella"))
            })
            .unwrap_or_else(|| PathBuf::from("stella-state"));
        Self { state }
    }

    pub fn db(&self) -> PathBuf {
        self.state.join("stella.db")
    }

    pub fn known(&self) -> PathBuf {
        self.state.join("known")
    }

    pub fn psl(&self) -> PathBuf {
        self.state.join("public_suffix_list.dat")
    }

    pub fn cache(&self) -> PathBuf {
        self.state.join("cache")
    }

    pub fn apk(&self) -> PathBuf {
        self.state.join("apk")
    }

    pub fn ensure(&self) -> std::io::Result<()> {
        for d in [self.state.clone(), self.known(), self.cache(), self.apk()] {
            std::fs::create_dir_all(d)?;
        }
        Ok(())
    }
}
