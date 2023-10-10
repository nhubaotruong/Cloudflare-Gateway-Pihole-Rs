use once_cell::sync::Lazy;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use reqwest::{header, Client, ClientBuilder};
use serde_json;

static CF_API_TOKEN: Lazy<String> = Lazy::new(|| match std::env::var("CF_API_TOKEN") {
    Ok(token) => token,
    Err(e) => panic!("Missing Cloudflare API token: {}", e),
});

static CF_IDENTIFIER: Lazy<String> = Lazy::new(|| match std::env::var("CF_IDENTIFIER") {
    Ok(identifier) => identifier,
    Err(e) => panic!("Missing Cloudflare identifier: {}", e),
});

static CLOUDFLARE_API_URL: Lazy<String> =
    Lazy::new(|| "https://api.cloudflare.com/client/v4/accounts/".to_owned() + &CF_IDENTIFIER);

// Create a static client to reuse the connection, with default header
static CLIENT: Lazy<Client> = Lazy::new(|| {
    let mut headers = header::HeaderMap::new();
    let auth_header_value_str = "Bearer ".to_owned() + CF_API_TOKEN.as_str();
    let auth_header_value = match header::HeaderValue::from_str(&auth_header_value_str) {
        Ok(value) => value,
        Err(e) => panic!("Error creating authorization header value: {}", e),
    };
    headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from(auth_header_value),
    );
    match ClientBuilder::new().default_headers(headers).build() {
        Ok(client) => client,
        Err(e) => panic!("Error creating client: {}", e),
    }
});

pub async fn get_cf_lists(prefix: &str) -> Vec<serde_json::Value> {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/lists";
    let resp = match CLIENT.get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .unwrap_or_else(|| {
                panic!(
                    "Error getting result from response in get_cf_lists: {}",
                    content
                )
            })
            .as_array()
            .unwrap_or_else(|| {
                panic!(
                    "Error getting array from result in get_cf_lists: {}",
                    content
                )
            })
            .par_iter()
            .filter_map(|line| {
                if line["name"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("Error getting name from line in get_cf_lists: {}", line)
                    })
                    .starts_with(prefix)
                {
                    Some(line.to_owned())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>(),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return content;
}

pub async fn create_cf_list(name: String, domains: Vec<&str>) -> serde_json::Value {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/lists";
    let resp = match CLIENT
        .post(&url)
        .json(&serde_json::json!({
            "name": name,
            "description": "Created by script.",
            "type": "DOMAIN",
            "items": domains
                .par_iter()
                .map(|d| serde_json::json!({"value": d}))
                .collect::<Vec<_>>(),
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .unwrap_or_else(|| {
                panic!(
                    "Error getting result from response in create_cf_list: {}",
                    content
                )
            })
            .to_owned(),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return content;
}

pub async fn delete_cf_list(id: &str) -> serde_json::Value {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/lists/" + id;
    let resp = match CLIENT.delete(&url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .unwrap_or_else(|| {
                panic!(
                    "Error getting result from response in delete_cf_list: {}",
                    content
                )
            })
            .to_owned(),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return content;
}

pub async fn get_gateway_policies(prefix: &str) -> Vec<serde_json::Value> {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/rules";
    let resp = match CLIENT.get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .unwrap_or_else(|| {
                panic!(
                    "Error getting result from response in get_gateway_policies: {}",
                    content
                )
            })
            .as_array()
            .unwrap_or_else(|| {
                panic!(
                    "Error getting array from result in get_gateway_policies: {}",
                    content
                )
            })
            .par_iter()
            .filter_map(|line| {
                if line["name"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!(
                            "Error getting name from line in get_gateway_policies: {}",
                            line
                        )
                    })
                    .starts_with(prefix)
                {
                    Some(line.to_owned())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>(),
        Err(e) => panic!("Error reading response: {}", e),
    };
    content
}

pub async fn create_gateway_policy(name: &str, list_ids: Vec<&str>) -> serde_json::Value {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/rules";
    let resp = match CLIENT
        .post(&url)
        .json(&serde_json::json!({
            "name": name,
            "description": "Created by script.",
            "action": "block",
            "enabled": true,
            "filters": ["dns"],
            "traffic": list_ids
                .par_iter()
                .map(|l| format!("any(dns.domains[*] in ${})", l))
                .collect::<Vec<_>>()
                .join(" or "),
            "rule_settings": {
                "block_page_enabled": false,
            },
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .unwrap_or_else(|| {
                panic!(
                    "Error getting result from response in create_gateway_policy: {}",
                    content
                )
            })
            .to_owned(),
        Err(e) => panic!("Error reading response: {}", e),
    };
    content
}

pub async fn update_gateway_policy(
    name: &str,
    policy_id: &str,
    list_ids: Vec<&str>,
) -> serde_json::Value {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/rules/" + policy_id;
    let resp = match CLIENT
        .put(&url)
        .json(&serde_json::json!({
            "name": name,
            "action": "block",
            "enabled": true,
            "filters": ["dns"],
            "traffic": list_ids
                .par_iter()
                .map(|l| format!("any(dns.domains[*] in ${})", l))
                .collect::<Vec<_>>()
                .join(" or "),
            "rule_settings": {
                "block_page_enabled": false,
            },
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .unwrap_or_else(|| {
                panic!(
                    "Error getting result from response in update_gateway_policy: {}",
                    content
                )
            })
            .to_owned(),
        Err(e) => panic!("Error reading response: {}", e),
    };
    content
}

pub async fn delete_gateway_policy(prefix: &str) -> i32 {
    let policy_id = match get_gateway_policies(prefix).await.first() {
        Some(policy) => policy["id"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "Error getting id from policy in delete_gateway_policy: {}",
                    policy
                )
            })
            .to_owned(),
        None => return 0,
    };
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/rules/" + policy_id.as_str();
    let resp = match CLIENT.delete(&url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .unwrap_or_else(|| {
                panic!(
                    "Error getting result from response in delete_gateway_policy: {}",
                    content
                )
            })
            .to_owned(),
        Err(e) => panic!("Error reading response: {}", e),
    };
    1
}
