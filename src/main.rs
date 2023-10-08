use futures::future::join_all;
use rayon::prelude::*;
use std::thread;
use std::time::Duration;
use tokio_uring;

mod cloudflare;
mod utils;

// #[tokio::main]
fn main() {
    let mut retries = 0;
    loop {
        match run() {
            Ok(_) => break,
            Err(_) => {
                retries += 1;
                if retries >= 3 {
                    eprintln!("Program failed after 3 retries");
                    break;
                } else {
                    eprintln!("Program panicked, retrying in 5 minutes...");
                    thread::sleep(Duration::from_secs(300));
                }
            }
        }
    }
    println!("Done!");
}

fn run() -> Result<(), ()> {
    let result = std::panic::catch_unwind(|| {
        tokio_uring::start(async {
            exec().await;
        });
    });
    match result {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

async fn exec() {
    let (black_list, white_list) = tokio::join!(
        utils::read_file_content_and_download("lists.txt", false),
        utils::read_file_content_and_download("whitelists.txt", true)
    );

    let mut block_list = black_list
        .difference(&white_list)
        .par_bridge()
        .cloned()
        .collect::<Vec<_>>();
    block_list.sort();
    println!("Black list size: {}", black_list.len());
    println!("White list size: {}", white_list.len());
    println!("Block list size: {}", block_list.len());

    // match tokio::fs::write("block_list.txt", block_list.join("\n")).await {
    //     Ok(_) => println!("Wrote {} block list to file", block_list.len()),
    //     Err(e) => println!("Error writing block list to file: {}", e),
    // }
    // return;

    let cf_prefix = "[AdBlock-DNS Block List]";
    let cf_lists = cloudflare::get_cf_lists(cf_prefix).await;
    println!("Cloudflare list size: {}", cf_lists.len());

    let sum_cf_lists_count = cf_lists
        .par_iter()
        .map(|list| list["count"].as_u64().unwrap())
        .sum::<u64>();

    if sum_cf_lists_count == block_list.len() as u64 {
        println!("No need to update.");
        return;
    }

    let policy_prefix = format!("{} Block Ads", cf_prefix);
    let deleted_policy = cloudflare::delete_gateway_policy(&policy_prefix).await;
    println!("Deleted {} gateway policies", deleted_policy);

    // Delete all lists parallely tokio
    let delete_list_tasks = cf_lists
        .par_iter()
        .map(|list| {
            let name = list["name"].as_str().unwrap();
            let id = list["id"].as_str().unwrap();
            println!("Deleting list {} - ID:{}", name, id);
            cloudflare::delete_cf_list(id)
        })
        .collect::<Vec<_>>();
    join_all(delete_list_tasks).await;

    // Create cf list by chunk of 1000 with name containing incremental number
    let create_list_tasks = block_list
        .par_chunks(1000)
        .enumerate()
        .map(|(i, chunk)| {
            let name = format!("{} {}", cf_prefix, i);
            println!("Creating list {}", name);
            let chunk_str_refs: Vec<&str> = chunk.par_iter().map(|s| s.as_str()).collect();
            cloudflare::create_cf_list(name, chunk_str_refs)
        })
        .collect::<Vec<_>>();
    let new_cf_list = join_all(create_list_tasks).await;
    let new_cf_list_ids = new_cf_list
        .par_iter()
        .map(|l| l["id"].as_str().unwrap())
        .collect::<Vec<_>>();

    let cf_policies = cloudflare::get_gateway_policies(&policy_prefix).await;
    if cf_policies.len() == 0 {
        println!("Creating firewall policy");
        cloudflare::create_gateway_policy(&policy_prefix, new_cf_list_ids).await;
    } else if cf_policies.len() != 1 {
        println!("More than one firewall policy found");
    } else {
        println!("Updating firewall policy");
        cloudflare::update_gateway_policy(
            &policy_prefix,
            cf_policies.first().unwrap()["id"].as_str().unwrap(),
            new_cf_list_ids,
        )
        .await;
    }
    return;
}
