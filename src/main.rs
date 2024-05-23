use futures::future::join_all;
use itertools::Itertools;
use std::error::Error;

mod cloudflare;
mod utils;

#[tokio::main]
async fn main() {
    let mut is_done = false;
    while !is_done {
        match exec().await {
            Ok(_) => {
                println!("Done!");
                is_done = true;
            }
            Err(e) => {
                println!("Error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(60 * 5)).await;
            }
        }
    }
}

async fn exec() -> Result<(), Box<dyn Error>> {
    let white_list = utils::read_file_content_and_download("whitelists.txt", true, None).await;
    let temp_list =
        utils::read_file_content_and_download("lists.txt", false, Some(white_list)).await;
    let black_list = temp_list.iter().sorted().collect::<Vec<_>>();

    println!("Black list size: {}", black_list.len());

    // match tokio::fs::write("block_list.txt", black_list.iter().join("\n")).await {
    //     Ok(_) => println!("Wrote {} block list to file", black_list.len()),
    //     Err(e) => println!("Error writing block list to file: {}", e),
    // }
    // return Ok(());

    let cf_prefix = "[AdBlock-DNS Block List]";
    let cf_lists = cloudflare::get_cf_lists(cf_prefix)
        .await
        .unwrap_or(Vec::<serde_json::Value>::new());
    println!("Cloudflare list size: {}", cf_lists.len());

    let sum_cf_lists_count = cf_lists
        .iter()
        .filter_map(|list| list["count"].as_u64())
        .sum::<u64>();

    if sum_cf_lists_count == black_list.len() as u64 {
        println!("No need to update.");
        return Ok(());
    }

    let policy_prefix = format!("{cf_prefix} Block Ads");
    let deleted_policy = cloudflare::delete_gateway_policy(&policy_prefix).await;
    println!("Deleted {deleted_policy} gateway policies");

    // Delete all lists parallely tokio
    let delete_list_tasks = cf_lists
        .iter()
        .filter_map(|list| {
            let name = list["name"].as_str();
            let id = list["id"].as_str();
            match (name, id) {
                (Some(name), Some(id)) => {
                    println!("Deleting list {name} - ID:{id}");
                    Some(cloudflare::delete_cf_list(id))
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    join_all(delete_list_tasks).await;

    // Create cf list by chunk of 1000 with name containing incremental number
    let create_list_tasks = black_list
        .chunks(1000)
        .enumerate()
        .map(|(i, chunk)| {
            let name = format!("{cf_prefix} {i}");
            let chunk_str_refs = chunk.iter().map(|&s| s).collect::<Vec<_>>();
            return cloudflare::create_cf_list(name, chunk_str_refs);
        })
        .collect::<Vec<_>>();
    let new_cf_list = join_all(create_list_tasks).await;
    let new_cf_list_ids = new_cf_list
        .iter()
        .filter_map(|l| Some(l.as_ref()?.get("id")?.as_str()?.to_owned()))
        .collect::<Vec<_>>();

    let expected_cf_list_count = new_cf_list.len();
    let actual_cf_list_count = new_cf_list_ids.len();

    let cf_policies = match cloudflare::get_gateway_policies(&policy_prefix).await {
        Some(cf_policies) => cf_policies,
        None => {
            println!("No cloudflare policy found");
            Vec::new()
        }
    };
    if cf_policies.len() == 0 {
        println!("Creating firewall policy");
        cloudflare::create_gateway_policy(&policy_prefix, &new_cf_list_ids).await;
    } else if cf_policies.len() != 1 {
        println!("More than one firewall policy found");
    } else {
        println!("Updating firewall policy");
        let cf_policy_id = cf_policies.first().and_then(|policy| policy["id"].as_str());
        match cf_policy_id {
            Some(cf_policy_id) => {
                cloudflare::update_gateway_policy(&policy_prefix, &cf_policy_id, &new_cf_list_ids)
                    .await;
            }
            None => {
                println!("No firewall policy found");
            }
        }
    }
    if expected_cf_list_count == actual_cf_list_count {
        return Ok(());
    }
    return Err(format!(
        "Not all lists are added, {actual_cf_list_count}/{expected_cf_list_count}"
    )
    .into());
}
