#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    Ads,
    Tracker,
    Telemetry,
    SelfHostedTelemetry,
}

const SELF_HOSTED_PRODUCTS: &[&str] =
    &["matomo", "piwik", "plausible", "umami", "fathom", "posthog"];

const TRACKER_PRODUCTS: &[&str] = &[
    "sgtm",
    "segment-proxy",
    "mixpanel-proxy",
    "adobe-fp",
    "snowplow",
    "rudderstack",
    "jitsu",
];

const TELEMETRY_PRODUCTS: &[&str] = &["apk-endpoint"];

const AD_SOURCE_PREFIXES: &[&str] = &[
    "adtech",
    "ads.txt",
    "app-ads.txt",
    "sellers",
    "intermediary",
    "prebid",
    "adguard-ads",
];

const TELEMETRY_SOURCE_PREFIXES: &[&str] = &["apk", "sdk", "extension"];

const PRODUCT_SUBCATEGORIES: &[(&str, &str)] = &[
    ("matomo", "matomo"),
    ("piwik", "matomo"),
    ("plausible", "plausible"),
    ("umami", "umami"),
    ("fathom", "fathom"),
    ("posthog", "posthog"),
    ("jitsu", "jitsu"),
    ("rudderstack", "rudderstack"),
    ("snowplow", "snowplow"),
    ("sgtm", "server-side-gtm"),
    ("segment-proxy", "segment"),
    ("mixpanel-proxy", "mixpanel"),
    ("adobe-fp", "adobe"),
];

pub const OTHER: &str = "other";
pub const MIN_COMPANY_ENTRIES: usize = 3;

pub fn product_subcategory<'a>(
    products: impl IntoIterator<Item = &'a str>,
) -> Option<&'static str> {
    let products: Vec<&str> = products.into_iter().collect();
    PRODUCT_SUBCATEGORIES
        .iter()
        .find(|(p, _)| products.contains(p))
        .map(|(_, s)| *s)
}

pub fn company(regdom: &str) -> String {
    let label = regdom.split('.').next().unwrap_or("");
    let slug: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    let slug = slug.trim_matches('-');
    if slug.is_empty() || slug == OTHER {
        OTHER.to_string()
    } else {
        slug.to_string()
    }
}

fn starts_with_any(source: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| source.starts_with(p))
}

impl Category {
    pub const ALL: [Self; 4] = [
        Self::Ads,
        Self::Tracker,
        Self::Telemetry,
        Self::SelfHostedTelemetry,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Self::Ads => "ads",
            Self::Tracker => "tracker",
            Self::Telemetry => "telemetry",
            Self::SelfHostedTelemetry => "self-hosted-telemetry",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Ads => "Stella Ads",
            Self::Tracker => "Stella Tracker",
            Self::Telemetry => "Stella Telemetry",
            Self::SelfHostedTelemetry => "Stella Self-Hosted Telemetry",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Ads => {
                "Ad serving, ad exchange and header bidding hosts found by active discovery and confirmed by how they answer"
            }
            Self::Tracker => {
                "Tracking, tag manager and collector hosts found by active discovery and confirmed by how they answer"
            }
            Self::Telemetry => {
                "App, SDK and extension telemetry hosts found by active discovery and confirmed by how they answer"
            }
            Self::SelfHostedTelemetry => {
                "Self-hosted analytics instances such as Matomo, Plausible, Umami and PostHog on first-party domains"
            }
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.slug() == slug)
    }

    pub fn of_product(product: &str) -> Option<Self> {
        if SELF_HOSTED_PRODUCTS.contains(&product) {
            Some(Self::SelfHostedTelemetry)
        } else if TRACKER_PRODUCTS.contains(&product) {
            Some(Self::Tracker)
        } else if TELEMETRY_PRODUCTS.contains(&product) {
            Some(Self::Telemetry)
        } else {
            None
        }
    }

    pub fn of_sources<'a>(sources: impl IntoIterator<Item = &'a str>) -> Self {
        let mut telemetry = false;
        for s in sources {
            if starts_with_any(s, AD_SOURCE_PREFIXES) {
                return Self::Ads;
            }
            telemetry |= starts_with_any(s, TELEMETRY_SOURCE_PREFIXES);
        }
        if telemetry {
            Self::Telemetry
        } else {
            Self::Tracker
        }
    }

    pub fn classify<'a>(
        products: impl IntoIterator<Item = &'a str>,
        sources: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        products
            .into_iter()
            .filter_map(Self::of_product)
            .min()
            .unwrap_or_else(|| Self::of_sources(sources))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_every_category() {
        for c in Category::ALL {
            assert_eq!(Category::from_slug(c.slug()), Some(c));
            assert!(c.title().starts_with("Stella "));
            assert!(!c.description().ends_with('.'));
        }
        assert_eq!(Category::from_slug("other"), None);
    }

    #[test]
    fn names_subcategories_by_product_or_company() {
        assert_eq!(product_subcategory(["collector", "umami"]), Some("umami"));
        assert_eq!(product_subcategory(["piwik"]), Some("matomo"));
        assert_eq!(product_subcategory(["sgtm"]), Some("server-side-gtm"));
        assert_eq!(product_subcategory(["collector"]), None);
        assert_eq!(company("pubmatic.com"), "pubmatic");
        assert_eq!(company("1800flowers.com"), "1800flowers");
        assert_eq!(company("-.io"), OTHER);
        assert_eq!(company("other.net"), OTHER);
    }

    #[test]
    fn products_decide_first() {
        assert_eq!(Category::classify(["snowplow"], []), Category::Tracker);
        assert_eq!(Category::classify(["rudderstack"], []), Category::Tracker);
        assert_eq!(
            Category::classify(["umami"], ["adtech"]),
            Category::SelfHostedTelemetry
        );
        assert_eq!(
            Category::classify(["collector", "sgtm"], ["apk"]),
            Category::Tracker
        );
        assert_eq!(
            Category::classify(["apk-endpoint", "matomo"], []),
            Category::Telemetry
        );
    }

    #[test]
    fn sources_decide_generic_products() {
        assert_eq!(
            Category::classify(["collector"], ["ct", "prebid-js"]),
            Category::Ads
        );
        assert_eq!(
            Category::classify(["pixel"], ["apk-config"]),
            Category::Telemetry
        );
        assert_eq!(
            Category::classify(["behaviour"], ["apk", "sellers.json"]),
            Category::Ads
        );
        assert_eq!(Category::classify(["twin"], ["ct"]), Category::Tracker);
        assert_eq!(Category::classify([], []), Category::Tracker);
    }
}
