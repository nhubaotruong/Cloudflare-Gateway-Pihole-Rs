use futures::future::join_all;
use once_cell::sync::Lazy;
use std::time::Duration;

use regex::Regex;
use reqwest::{header, Client};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use tokio::fs::read_to_string;

pub async fn read_file_content_and_download(name: &str, skip_filter: bool) -> HashSet<String> {
    let urls = read_file_content(&name).await;
    let content = get_content_from_urls(&urls, &skip_filter).await;
    return content;
}

pub async fn read_file_content(name: &str) -> Vec<String> {
    let content = match read_to_string(name).await {
        Ok(content) => content
            .lines()
            .filter_map(|line| {
                if line.starts_with('#') {
                    return None;
                }
                return Some(line.to_string());
            })
            .collect::<Vec<_>>(),
        Err(e) => panic!("Error reading file: {}", e),
    };
    return content;
}

static CLIENT: Lazy<Client> = Lazy::new(|| {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::ACCEPT_ENCODING,
        header::HeaderValue::from_static("gzip, deflate, br"),
    );
    let client = Client::builder()
        .default_headers(headers)
        .pool_idle_timeout(Some(Duration::from_secs(600)))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .build()
        .unwrap();
    return client;
});

async fn get_content_from_urls(urls: &Vec<String>, skip_filter: &bool) -> HashSet<String> {
    let tasks = urls
        .iter()
        .map(|url| download_content(&url))
        .collect::<Vec<_>>();
    let content = join_all(tasks)
        .await
        .iter()
        .map(|x| x.lines())
        .flatten()
        .filter_map(filter_domain)
        .collect::<HashSet<_>>();

    if *skip_filter {
        return content;
    }

    return filter_subdomain(&content);
}

fn filter_subdomain(filtered_content: &HashSet<String>) -> HashSet<String> {
    let mut domain_map: HashMap<Cow<String>, HashSet<Cow<String>>> = HashMap::new();

    for domain in filtered_content {
        let splitted = domain.split('.').collect::<Vec<_>>();
        if splitted.len() <= 1 {
            continue;
        }
        let domain_part = splitted[splitted.len() - 2..].join(".");
        domain_map
            .entry(Cow::Owned(domain_part))
            .or_insert(HashSet::new())
            .insert(Cow::Borrowed(domain));
    }

    let filtered_domains = domain_map
        .iter()
        .filter_map(|(domain_part, domain_names)| {
            if domain_names.contains(domain_part) {
                Some(HashSet::from([domain_part.to_string()]))
            } else {
                Some(
                    domain_names
                        .iter()
                        .map(|l| l.to_string())
                        .collect::<HashSet<_>>(),
                )
            }
        })
        .flatten()
        .collect::<HashSet<_>>();
    return filtered_domains;
}

async fn download_content(url: &str) -> String {
    let resp = match CLIENT.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.text().await {
        Ok(content) => content,
        Err(e) => panic!("Error reading response: {}", e),
    };
    println!("Downloaded: {} . File size: {}", url, content.len());
    return content;
}

static REPLACE_PATTERN: Lazy<Regex> =
    Lazy::new(
        || match Regex::new(r"(^([0-9.]+|[0-9a-fA-F:.]+)\s+|^(\|\||@@\|\|?|\*\.|\*))") {
            Ok(re) => re,
            Err(e) => panic!("Error compiling regex: {}", e),
        },
    );

static DOMAIN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    match Regex::new(
        r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$",
    ) {
        Ok(re) => re,
        Err(e) => panic!("Error compiling regex: {}", e),
    }
});

static IP_PATTERN: Lazy<Regex> =
    Lazy::new(
        || match Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
            Ok(re) => re,
            Err(e) => panic!("Error compiling regex: {}", e),
        },
    );

fn filter_domain(line: &str) -> Option<String> {
    let domain = line.trim();
    if domain.starts_with('#')
        || domain.starts_with('!')
        || domain.starts_with('/')
        || domain.is_empty()
    {
        return None;
    }

    let domain = domain
        .to_lowercase()
        .split('#')
        .next()
        .and_then(|x| x.split('^').next())
        .and_then(|x| x.split('$').next())
        .and_then(|x| Some(x.replace('\r', "")))
        .and_then(|x| Some(x.trim().to_string()))
        .and_then(|x| Some(x.trim_start_matches("*.").to_string()))
        .and_then(|x| Some(x.trim_start_matches(".").to_string()))
        .and_then(|x| Some(REPLACE_PATTERN.replace_all(&x, "").to_string()))
        .and_then(|x| match idna::domain_to_ascii(&x) {
            Ok(domain) => Some(domain),
            Err(_) => None,
        })
        .and_then(|x| {
            if !DOMAIN_PATTERN.is_match(&x) || IP_PATTERN.is_match(&x) {
                None
            } else {
                Some(x)
            }
        })
        .and_then(|x| Some(x.trim_start_matches("www.").to_string()));

    return domain;
}
