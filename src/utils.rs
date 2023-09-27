use futures::future::join_all;
use once_cell::sync::Lazy;
use radix_trie::Trie;
use rayon::prelude::*;
use regex::Regex;
use reqwest::Client;
use std::collections::HashSet;
use tokio::fs::read_to_string;

pub async fn read_file_content_and_download(name: &str) -> HashSet<String> {
    let urls = read_file_content(name).await;
    let content = get_content_from_urls(urls).await;
    return content;
}

async fn read_file_content(name: &str) -> Vec<String> {
    let content = match read_to_string(name).await {
        Ok(content) => content
            .par_lines()
            .filter_map(|line| {
                if line.starts_with('#') {
                    None
                } else {
                    Some(line.to_string())
                }
            })
            .collect::<Vec<_>>(),
        Err(e) => panic!("Error reading file: {}", e),
    };
    return content;
}

async fn get_content_from_urls(urls: Vec<String>) -> HashSet<String> {
    let client = Client::new();
    let tasks = urls
        .par_iter()
        .map(|url| download_content(url, &client))
        .collect::<Vec<_>>();
    let content: Vec<String> = join_all(tasks)
        .await
        .par_iter()
        .map(|x| x.to_string())
        .collect();
    let filtered_content: HashSet<String> = content
        .par_iter()
        .map(|text| {
            text.split("\n")
                .par_bridge()
                .filter_map(|x| filter_domain(&x))
        })
        .flatten()
        .collect();

    let mut trie = Trie::new();

    for domain in &filtered_content {
        let splitted = domain.rsplit('.').collect::<Vec<_>>();
        trie.insert(
            splitted
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join("."),
            (),
        );
    }

    let filtered_domains: HashSet<_> = filtered_content
        .into_iter()
        .filter(|domain| {
            let parts: Vec<_> = domain.split('.').collect();
            if parts.len() <= 1 {
                return false;
            }
            if parts.len() == 2 {
                return true;
            }
            let reverted_parts = parts.iter().rev().collect::<Vec<_>>();
            let reverted_domain = reverted_parts
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(".");
            let suffix = &reverted_domain[reverted_parts[0..2]
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(".")
                .len()
                + 1..];
            !trie.get_raw_descendant(suffix).is_some()
        })
        .collect();

    return filtered_domains;
}

async fn download_content(url: &str, client: &Client) -> String {
    let resp = match client.get(url).send().await {
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
        .and_then(|x| Some(REPLACE_PATTERN.replace_all(&x, "").into_owned()))
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
        });

    return domain;
}
