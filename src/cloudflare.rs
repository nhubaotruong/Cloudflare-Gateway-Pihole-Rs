use once_cell::sync::Lazy;
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

pub async fn get_cf_lists(prefix: &str) -> Option<Vec<serde_json::Value>> {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/lists";
    let resp = match CLIENT.get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .and_then(|result| result.as_array())
            .and_then(|result_array| {
                Some(
                    result_array
                        .iter()
                        .filter_map(|line| match line["name"].as_str() {
                            Some(name) if name.starts_with(prefix) => Some(line.to_owned()),
                            _ => None,
                        }),
                )
            })
            .and_then(|result| Some(result.collect::<Vec<_>>())),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return content;
}

pub async fn create_cf_list(name: String, domains: Vec<&String>) -> Option<serde_json::Value> {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/lists";
    let resp = match CLIENT
        .post(&url)
        .json(&serde_json::json!({
            "name": name,
            "description": "Created by script.",
            "type": "DOMAIN",
            "items": domains
                .iter()
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
            .and_then(|result| Some(result.to_owned())),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return content;
}

pub async fn delete_cf_list(id: &str) -> Option<serde_json::Value> {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/lists/" + id;
    let resp = match CLIENT.delete(&url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .and_then(|result| Some(result.to_owned())),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return content;
}

pub async fn get_gateway_policies(prefix: &str) -> Option<Vec<serde_json::Value>> {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/rules";
    let resp = match CLIENT.get(&url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    let content = match resp.json::<serde_json::Value>().await {
        Err(e) => panic!("Error reading response: {}", e),
        Ok(content) => content
            .get("result")
            .and_then(|result| result.as_array())
            .and_then(|result_array| {
                Some(
                    result_array
                        .iter()
                        .filter_map(|line| match line["name"].as_str() {
                            Some(name) if name.starts_with(prefix) => Some(line.to_owned()),
                            _ => None,
                        }),
                )
            })
            .and_then(|result| Some(result.collect::<Vec<_>>())),
    };
    return content;
}

pub async fn create_gateway_policy(name: &str, list_ids: Vec<String>) -> Option<serde_json::Value> {
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
                .iter()
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
            .and_then(|result| Some(result.to_owned())),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return content;
}

pub async fn update_gateway_policy(
    name: &str,
    policy_id: &str,
    list_ids: Vec<String>,
) -> Option<serde_json::Value> {
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/rules/" + policy_id;
    let resp = match CLIENT
        .put(&url)
        .json(&serde_json::json!({
            "name": name,
            "action": "block",
            "enabled": true,
            "filters": ["dns"],
            "traffic": list_ids
                .iter()
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
            .and_then(|result| Some(result.to_owned())),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return content;
}

pub async fn delete_gateway_policy(prefix: &str) -> i32 {
    let policies = match get_gateway_policies(prefix).await {
        Some(policies) => policies,
        None => return 0,
    };
    let policy_id = match policies.first() {
        Some(policy) => policy["id"].as_str().and_then(|x| Some(x.to_owned())),
        None => return 0,
    };
    let policy_id_str = match policy_id {
        Some(policy_id) => policy_id,
        None => return 0,
    };
    let url = CLOUDFLARE_API_URL.to_string() + "/gateway/rules/" + &policy_id_str;
    let resp = match CLIENT.delete(&url).send().await {
        Ok(resp) => resp,
        Err(e) => panic!("Error sending request: {}", e),
    };
    match resp.json::<serde_json::Value>().await {
        Ok(content) => content
            .get("result")
            .and_then(|result| Some(result.to_owned())),
        Err(e) => panic!("Error reading response: {}", e),
    };
    return 1;
}
