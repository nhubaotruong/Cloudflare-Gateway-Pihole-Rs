use futures::future::join_all;
use itertools::Itertools;
use rayon::prelude::*;
use std::collections::HashSet;
use std::error::Error;

mod cloudflare;
mod utils;

#[tokio::main]
async fn main() {
    match exec().await {
        Ok(_) => println!("Done!"),
        Err(e) => panic!("Error: {}", e),
    }
}

async fn exec() -> Result<(), Box<dyn Error>> {
    let (black_list, white_list) = tokio::join!(
        utils::read_file_content_and_download("lists.txt", true),
        utils::read_file_content_and_download("whitelists.txt", true)
    );

    // Custom microsoft whitelist
    let microsoft_whitelist = utils::read_file_content("microsoft_whitelist.txt")
        .await
        .par_iter()
        .filter_map(|line| utils::filter_domain(line))
        .collect::<HashSet<_>>();

    let combined_white_list = white_list
        .par_iter()
        .chain(microsoft_whitelist.par_iter())
        .cloned()
        .collect::<HashSet<_>>();

    let unsorted_block_list = black_list
        .difference(&combined_white_list)
        .par_bridge()
        .cloned()
        .collect::<Vec<_>>();

    let sorted_block_list = unsorted_block_list
        .iter()
        .sorted()
        .cloned()
        .collect::<Vec<_>>();

    println!("Black list size: {}", black_list.len());
    println!("White list size: {}", white_list.len());
    println!("Block list size: {}", sorted_block_list.len());

    // match tokio::fs::write("block_list.txt", sorted_block_list.join("\n")).await {
    //     Ok(_) => println!("Wrote {} block list to file", sorted_block_list.len()),
    //     Err(e) => println!("Error writing block list to file: {}", e),
    // }
    // return Ok(());

    let cf_prefix = "[AdBlock-DNS Block List]";
    let cf_lists = match cloudflare::get_cf_lists(cf_prefix).await {
        Some(cf_lists) => cf_lists,
        None => {
            println!("No cloudflare list found");
            return Ok(());
        }
    };
    println!("Cloudflare list size: {}", cf_lists.len());

    let sum_cf_lists_count = cf_lists
        .par_iter()
        .filter_map(|list| list["count"].as_u64())
        .sum::<u64>();

    if sum_cf_lists_count == sorted_block_list.len() as u64 {
        println!("No need to update.");
        return Ok(());
    }

    let policy_prefix = format!("{cf_prefix} Block Ads");
    let deleted_policy = cloudflare::delete_gateway_policy(&policy_prefix).await;
    println!("Deleted {deleted_policy} gateway policies");

    // Delete all lists parallely tokio
    let delete_list_tasks = cf_lists
        .par_iter()
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
    let create_list_tasks = sorted_block_list
        .par_chunks(1000)
        .enumerate()
        .map(|(i, chunk)| {
            let name = format!("{cf_prefix} {i}");
            println!("Creating list {name}");
            let chunk_str_refs: Vec<&str> = chunk.par_iter().map(|s| s.as_str()).collect();
            cloudflare::create_cf_list(name, chunk_str_refs)
        })
        .collect::<Vec<_>>();
    let new_cf_list = join_all(create_list_tasks).await;
    let new_cf_list_ids = new_cf_list
        .par_iter()
        .filter_map(|l| Some(l.to_owned()?.get("id")?.as_str()?.to_owned()))
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
        cloudflare::create_gateway_policy(&policy_prefix, new_cf_list_ids).await;
    } else if cf_policies.len() != 1 {
        println!("More than one firewall policy found");
    } else {
        println!("Updating firewall policy");
        let cf_policy_id = cf_policies.first().and_then(|policy| policy["id"].as_str());
        match cf_policy_id {
            Some(cf_policy_id) => {
                cloudflare::update_gateway_policy(&policy_prefix, cf_policy_id, new_cf_list_ids)
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
