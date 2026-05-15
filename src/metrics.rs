use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

const DURATION_BUCKETS: &[f64] = &[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

pub struct Metrics {
    pub http_requests: Family<RouteLabels, Counter>,
    pub dav_duration: Family<DavOpLabels, Histogram>,
    pub oo_callbacks: Family<CallbackLabels, Counter>,
    pub session_refreshes: Counter,
    registry: Registry,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let http_requests = Family::default();
        registry.register(
            "office_portal_http_requests_total",
            "HTTP requests by route and status",
            http_requests.clone(),
        );

        fn make_histogram() -> Histogram {
            Histogram::new(DURATION_BUCKETS.iter().copied())
        }
        let dav_duration = Family::new_with_constructor(make_histogram as fn() -> Histogram);
        registry.register(
            "office_portal_dav_duration_seconds",
            "WebDAV operation latency",
            dav_duration.clone(),
        );

        let oo_callbacks = Family::default();
        registry.register(
            "office_portal_oo_callbacks_total",
            "OnlyOffice callback results",
            oo_callbacks.clone(),
        );

        let session_refreshes = Counter::default();
        registry.register(
            "office_portal_session_refreshes_total",
            "OIDC token refresh attempts",
            session_refreshes.clone(),
        );

        Self {
            http_requests,
            dav_duration,
            oo_callbacks,
            session_refreshes,
            registry,
        }
    }

    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &self.registry)?;
        Ok(buf)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouteLabels {
    pub route: &'static str,
    pub status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DavOpLabels {
    pub op: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CallbackLabels {
    pub result: &'static str,
}
