use fastly::convert::{ToHeaderValue, ToStatusCode};
use fastly::experimental::BackendHealth;
use fastly::http::header::{ACCEPT_ENCODING, COOKIE, LOCATION, USER_AGENT};
use fastly::http::Url;
use fastly::{experimental::BackendExt, Backend, ConfigStore, Error, Request, Response};
use itertools::Itertools;
use rand::distributions::WeightedIndex;
use rand::prelude::Distribution;
use rand::thread_rng;
use uuid::Uuid;

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // TODO: read these from a config file or Fastly config store
    let active_ab_tests = vec![ABTest {
        name: "BankHolidaysTest".into(),
        expires: 86400,
        variants: vec![
            ABVariant {
                name: "A".into(),
                weight: 99,
            },
            ABVariant {
                name: "B".into(),
                weight: 1,
            },
        ],
    }];

    // TODO: this works differently in C@E, rewrite
    req.set_header("Fastly-Purge-Requires-Auth", "1");

    let client_ip = req.get_client_ip_addr().unwrap().to_string();
    if is_in_list("ip_denylist", &client_ip) {
        return forbidden();
    }

    if req.get_url().scheme() != "https" {
        return redirect_to_https(req.get_url().clone());
    }

    if let Some(ja3_signature) = req.get_tls_ja3_md5().map(hex::encode) {
        if is_in_list("ja3_denylist", &ja3_signature) {
            return forbidden();
        }
        req.set_header("Client-JA3", &ja3_signature);
    }

    if is_compressed_file_format(req.get_path()) {
        req.remove_header(ACCEPT_ENCODING);
    }

    match req.get_path().to_lowercase().as_str() {
        "/autodiscover/autodiscover.xml" => return not_found(),
        "/.well-known/security.txt" | "/.well_known/security.txt" | "/security.txt" => {
            return redirect(
                302,
                "https://vdp.cabinetoffice.gov.uk/.well-known/security.txt",
            )
        }
        _ => (),
    }

    sort_and_sanitise_query_string(&mut req)?;

    req.set_stale_while_revalidate(24 * 60 * 60);

    req.set_header("GOVUK-Request-Id", Uuid::new_v4().to_string());

    if req.get_path() == "/" || req.get_path().to_lowercase().starts_with("/alerts") {
        req.remove_query();
    }

    if let Some(session_cookie) =
        find_cookie(&req, "__Host-govuk_account_session").map(str::to_owned)
    {
        req.set_header("GOVUK-Account-Session", session_cookie);
        req.set_header("GOVUK-Account-Session-Exists", "1");
        // TODO: need to pull in a dependency to do regex, will do it later
        // if (req.http.GOVUK-Account-Session ~ "\$\$(.+)$") {
        //     set req.http.GOVUK-Account-Session-Flash = re.group.1;
        // }
    }

    // TODO: only do this if we have active A/B tests
    // TODO: should probably parse the value of the cookie policy cookie instead of just using str#contains
    if find_cookie(&req, "cookies_policy").is_some_and(|s| s.contains("%22usage%22:true")) {
        req.set_header("Usage-Cookies-Opt-In", "true");

        for test in active_ab_tests {
            // Always choose the first variant for the crawler
            let chosen_variant = if req
                .get_header_str(USER_AGENT)
                .is_some_and(|s| s.starts_with("GOV.UK Crawler Worker"))
            {
                test.default_variant()
            }
            // Otherwise, if the variant was passed through a query param and is valid, use that
            else if let Some(name) = req.get_query_parameter(&format!("ABTest-{}", test.name)) {
                test.find_variant(name).unwrap_or(test.default_variant())
            }
            // Otherwise, if a cookie is set and is valid, use that
            else if let Some(name) = find_cookie(&req, &format!("ABTest-{}", test.name)) {
                if let Some(variant) = test.find_variant(name) {
                    req.set_header(
                        &format!("GOVUK-ABTest-{}-Cookie", test.name),
                        "sent_in_request",
                    );
                    variant
                } else {
                    test.default_variant()
                }
            }
            // Otherwise, choose a variant using weighted RNG
            else {
                let distribution =
                    WeightedIndex::new(test.variants.iter().map(|v| v.weight)).unwrap();
                &test.variants[distribution.sample(&mut thread_rng())]
            };
            req.set_header(format!("GOVUK-ABTest-{}", test.name), &chosen_variant.name);
        }
    }

    let response = fetch_with_failover(req);

    // TODO: process the response before returning it (vcl_deliver)

    Ok(response)
}

fn fetch_with_failover(mut req: Request) -> Response {
    if let Some(response) = try_backend("origin", req.clone_with_body()) {
        return response;
    }

    req.set_stale_while_revalidate(0);
    req.set_header("Fastly-Failover", "1");
    req.set_path(&remove_duplicate_slashes(req.get_path()));
    if req.get_path() == "/" {
        req.set_path("/index.html")
    } else if !has_known_file_extension(req.get_path()) {
        req.set_path(&format!("{}.html", req.get_path()));
    }

    if let Some(mut response) = try_backend("mirrorS3", req.clone_with_body()) {
        if response.get_status() != 200 {
            response.set_status(503);
        }
        return response;
    }

    if let Some(mut response) = try_backend("mirrorS3Replica", req.clone_with_body()) {
        if response.get_status() != 200 {
            response.set_status(503);
        }
        return response;
    }

    // TODO:
    // set req.url = "/<%= config.fetch('gcs_mirror_prefix') %>" req.url;
    // set req.http.Date = now;
    // set req.http.Authorization = "AWS <%= config.fetch('gcs_mirror_access_id') %>:" digest.hmac_sha1_base64("<%= config.fetch('gcs_mirror_secret_key') %>", "GET" LF LF LF now LF "/<%= config.fetch('gcs_mirror_bucket_name') %>" req.url.path);

    if let Some(mut response) = try_backend("mirrorGCS", req) {
        if response.get_status() != 200 {
            response.set_status(503);
        }
        return response;
    }

    Response::from_status(500)
}

fn try_backend(backend_name: &str, mut req: Request) -> Option<Response> {
    if backend_health(backend_name) == BackendHealth::Unhealthy {
        return None;
    }
    req.set_header("Fastly-Backend-Name", backend_name);
    let response = req.send(backend_name).ok()?;
    if response.get_status().is_server_error() {
        None
    } else {
        Some(response)
    }
}

fn backend_health(backend_name: &str) -> BackendHealth {
    Backend::from_name(backend_name)
        .unwrap()
        .is_healthy()
        .unwrap_or(BackendHealth::Unknown)
}

fn not_found() -> Result<Response, Error> {
    Ok(Response::from_status(404)
        .with_header("Fastly-Backend-Name", "force_not_found")
        .with_body_text_html(include_str!("404.html")))
}

fn forbidden() -> Result<Response, Error> {
    Ok(Response::from_status(403).with_body_text_plain("Forbidden"))
}

fn is_in_list(list_name: &str, value: &str) -> bool {
    ConfigStore::open(list_name).get(value).as_deref() == Some("true")
}

fn redirect(status: impl ToStatusCode, location: impl ToHeaderValue) -> Result<Response, Error> {
    return Ok(Response::from_status(status).with_header(LOCATION, location));
}

fn redirect_to_https(mut url: Url) -> Result<Response, Error> {
    url.set_scheme("https")
        .expect("https is guaranteed to be a valid scheme");
    redirect(301, url)
}

fn is_compressed_file_format(path: &str) -> bool {
    let path = path.to_lowercase();
    [
        ".jpeg", ".jpg", ".png", ".gif", ".gz", ".tgz", ".bz2", ".tbz", ".zip", ".flv", ".pdf",
        ".mp3", ".ogg",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
}

fn sort_and_sanitise_query_string(req: &mut Request) -> Result<(), Error> {
    let mut qs: Vec<(String, String)> = req.get_query()?;
    qs.retain(|(key, _)| !key.to_lowercase().starts_with("utm_"));
    qs.sort_by(|(a, _), (b, _)| a.cmp(b));
    req.set_query(&qs)?;
    Ok(())
}

fn get_cookies(req: &Request) -> impl Iterator<Item = (&str, &str)> {
    req.get_header_str(COOKIE)
        .unwrap_or("")
        .split("; ")
        .filter_map(|cookie| cookie.split_once("="))
}

fn find_cookie<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    get_cookies(&req).find_map(|(k, v)| if k == name { Some(v) } else { None })
}

fn remove_duplicate_slashes(path: &str) -> String {
    path.split("/").filter(|s| !s.is_empty()).join("/")
}

fn has_known_file_extension(path: &str) -> bool {
    let path = path.to_lowercase();
    [
        ".atom", ".chm", ".css", ".csv", ".diff", ".doc", ".docx", ".dot", ".dxf", ".eps", ".gif",
        ".gml", ".html", ".ico", ".ics", ".jpeg", ".jpg", ".js", ".json", ".kml", ".odp", ".ods",
        ".odt", ".pdf", ".png", ".ppt", ".pptx", ".ps", ".rdf", ".rtf", ".sch", ".txt", ".wsdl",
        ".xls", ".xlsm", ".xlsx", ".xlt", ".xml", ".xsd", ".xslt", ".zip",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
}

struct ABVariant {
    name: String,
    weight: u32,
}

struct ABTest {
    name: String,
    expires: u32,
    variants: Vec<ABVariant>,
}

impl ABTest {
    fn default_variant(&self) -> &ABVariant {
        &self.variants[0]
    }

    fn find_variant(&self, name: &str) -> Option<&ABVariant> {
        self.variants.iter().find(|v| v.name == name)
    }
}
