use anyhow::{Context, Result};
use aptos_api_types::{
    transaction::UserTransactionRequestInner, AccountData, Address, Ed25519Signature,
    EntryFunctionId, HexEncodedBytes, SubmitTransactionRequest, TransactionSignature, U64,
};
use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, ED25519_SIGNATURE_LENGTH},
    PrivateKey, ValidCryptoMaterialStringExt,
};
use aptos_types::{
    account_address::{self, AccountAddress},
    chain_id::ChainId,
};
use clap::Args;
use futures::{stream::FuturesUnordered, StreamExt as _};
use reqwest::{Client, Response, Url};
use std::{
    future::Future,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        OnceLock,
    },
    time::{Duration, Instant, SystemTime},
    u64,
};
use tokio::time;

const CONTENT_TYPE: &str = "application/json";

const DESTINATION_ACCOUNT_ADDRESS: &str =
    "0x0101010101010101010101010101010101010101010101010101010101010101";

/// Shared http client to be reused across multiple requests.
static HTTP_CLIENT: OnceLock<Vec<Client>> = OnceLock::new();

static RPC_URL: OnceLock<Url> = OnceLock::new();
static CHAIN_ID: OnceLock<ChainId> = OnceLock::new();

fn get_rpc_url() -> Url {
    RPC_URL.get().cloned().expect("RPC URL must be set")
}
fn get_http_client() -> Client {
    static ROUND: AtomicUsize = AtomicUsize::new(0);
    let clients = HTTP_CLIENT.get().expect("HTTP client must be set");
    // Unwrap is safe because it is bounded by the number of clients.
    clients
        .get(ROUND.fetch_add(1, Relaxed) % clients.len())
        .cloned()
        .unwrap()
}
// Make it easier to access the arguments concurrently.
static LOAD_ARGS: OnceLock<LoadTrafficArgs> = OnceLock::new();

fn max_retry() -> u64 {
    1
}
fn backoff_ms() -> u64 {
    0
}
fn traffic_concurrency() -> u64 {
    LOAD_ARGS
        .get()
        .expect("Concurrency must be set")
        .concurrency as u64
}
fn max_loop() -> u64 {
    LOAD_ARGS
        .get()
        .expect("Loop account must be set")
        .loop_count as u64
}
fn mode() -> u64 {
    LOAD_ARGS.get().expect("Mode must be set").mode as u64
}
#[derive(Debug, Args, Clone)]
pub struct LoadTrafficArgs {
    #[arg(short, long)]
    pub rpc_url: String,
    /// Account private key. Used to derive the account address and its public key.
    #[arg(short, long)]
    pub key: String,
    /// Number of accounts to submit transactions concurrently.
    #[arg(short, long, value_parser = 1..=4294967295)]
    pub concurrency: i64,
    /// Traffic loop count.
    #[arg(short, long, default_value_t = i64::MAX, value_parser = 1..)]
    pub loop_count: i64,
    /// Number of clients to be used for HTTP requests. For high concurrency,
    /// if the bottleneck is the client, increase this number.
    #[arg(short, long, default_value_t = 1, value_parser = 1..)]
    pub shards: i64,
    /// HTTP request timeout in seconds from when the request starts connecting
    /// until the response body has finished.
    #[arg(short='t', long, default_value_t = 5, value_parser = 1..)]
    pub request_timeout: i64,
    /// Timeout for idle sockets being kept-alive. Recommended to be larger than request_timeout
    /// but smaller than wait_time.
    #[arg(short, long, default_value_t = 10, value_parser = 1..)]
    pub pool_idle_timeout: i64,

    /// Traffic mode:
    /// 0 - post simulation and get resource
    /// 1 - post simulation only
    /// 2 - get resource only
    #[arg(short, long, default_value_t = 0, value_parser = 0..3)]
    pub mode: i64,
}

impl LoadTrafficArgs {
    pub async fn run(self) -> Result<()> {
        let rpc_url = Url::parse(&self.rpc_url).context("Failed to parse RPC URL")?;

        let timeout = Duration::from_secs(self.request_timeout as u64);
        let pool_idle_timeout = Duration::from_secs(self.pool_idle_timeout as u64);
        let http_clients = (0..self.shards)
            .map(|_| {
                Client::builder()
                    .timeout(timeout)
                    .pool_idle_timeout(pool_idle_timeout)
                    .build()
                    .unwrap()
            })
            .collect();
        HTTP_CLIENT
            .set(http_clients)
            .expect("HTTP client must be set once");
        RPC_URL
            .set(rpc_url.clone())
            .expect("RPC URL must be set once");
        let chain_id = ChainId::test();
        CHAIN_ID.set(chain_id).expect("Chain ID must be set once");

        let private_key = Ed25519PrivateKey::from_encoded_string(&self.key).unwrap();
        // Arguments are set, store it for later use.
        LOAD_ARGS
            .set(self.clone())
            .expect("Load traffic args must be set once");

        println!(
            "Starting traffic loop with {count} iterations on chain={chain_id}",
            count = self.loop_count
        );

        let loader = TrafficLoader::new(private_key).await?;

        let result = loader.start_traffic().await;
        println!("Traffic loader stopped with result: {result:?}");
        result
    }
}

pub struct TrafficLoader {
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    account_address: AccountAddress,
}

impl TrafficLoader {
    pub async fn new(private_key: Ed25519PrivateKey) -> Result<Self> {
        let public_key = private_key.public_key();
        let account_address = account_address::from_public_key(&public_key);

        Ok(Self {
            private_key,
            public_key,
            account_address,
        })
    }

    pub async fn start_traffic(self) -> Result<()> {
        let (src_account, expected_sequence_number) =
            get_sequence_number(self.account_address).await?;
        println!("Source account {src_account} has sequence number {expected_sequence_number}",);
        for loop_count in 0..max_loop() {
            println!("Loop {loop_count}: starting ...");
            // Submit transactions concurrently.
            let requests = (0..traffic_concurrency())
                .map(|_| {
                    create_simulate_request(
                        src_account.into(),
                        self.public_key.to_string().as_str(),
                        expected_sequence_number,
                    )
                })
                .collect::<Vec<_>>();
            let now = Instant::now();
            let mut task_handles = Vec::new();

            if mode() == 0 || mode() == 1 {
                task_handles.push(tokio::spawn(async move {
                    let _responses = run_concurrent_actions(
                        requests,
                        post_simulate_request,
                        max_retry(),
                        backoff_ms(),
                        "Submitting traffic transactions",
                    )
                    .await;
                    // println!("All response statuses: {statuses:?}", statuses = responses.iter().map(|(_, r)| r.status()).collect::<Vec<_>>());
                }));
            }
            if mode() == 0 || mode() == 2 {
                task_handles.push(tokio::spawn(async move {
                    let requests = (0..traffic_concurrency())
                        .map(|_| {
                            (
                                AccountAddress::from_str_strict(DESTINATION_ACCOUNT_ADDRESS).unwrap(),
                                "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                            )
                        })
                        .collect::<Vec<_>>();
                    let _responses = run_concurrent_actions(
                        requests,
                        get_account_resource_by_tag,
                        max_retry(),
                        backoff_ms(),
                        "Getting account resource",
                    )
                    .await;
                }))
            };

            for handle in task_handles {
                let _ = handle.await;
            }

            println!(
                "Loop {loop_count}: traffic transactions take {d} ms",
                d = now.elapsed().as_millis()
            );
        }

        Ok(())
    }
}

/// Try perform task concurrently with retry.
///
/// The successful responses are returned, and it may contains fewer elements than the input actions
/// if there are remaining failures after retry is exhausted.
async fn run_concurrent_actions<Fut, F, A, R>(
    mut actions: Vec<A>,
    task_fn: F,
    max_retry: u64,
    backoff_ms: u64,
    context: &str,
) -> Vec<(A, R)>
where
    F: Fn(A) -> Fut,
    Fut: Future<Output = anyhow::Result<(A, R)>>,
    A: PartialEq + Clone + Send + 'static,
{
    let total_actions = actions.len();
    let instant_start = Instant::now();
    println!("{context} started, total requests: {total_actions}");
    let mut success_responses = Vec::new();
    for i in 0..max_retry {
        {
            let mut query_futures = actions
                .iter()
                .map(|act| task_fn(act.clone()))
                .collect::<FuturesUnordered<_>>();

            while let Some(result) = query_futures.next().await {
                match result {
                    Err(e) => {
                        println!("{e}");
                    },
                    Ok(pair) => {
                        success_responses.push(pair);
                    },
                }
            }
        }

        // Get the failed actions and retry them.
        actions.retain(|account| !success_responses.iter().any(|(acc, _)| acc == account));
        // All actions are finished.
        if actions.is_empty() || total_actions == success_responses.len() {
            break;
        }
        let remaining_failures = actions.len();
        let remaining_failure_rate = remaining_failures as f64 / total_actions as f64;

        // Calculate backoff time based on retry count and failure rate.
        let backoff = (remaining_failure_rate * backoff_ms as f64 * i as f64) as u64;
        println!("{context} [try {i}]: remaining failure rate {remaining_failure_rate:.5}. Retrying {remaining_failures} actions after {backoff} milliseconds ...",);
        time::sleep(Duration::from_millis(backoff)).await;
    }
    println!(
        "{context} finished, total success responses {}. Time spent: {d} ms",
        success_responses.len(),
        d = instant_start.elapsed().as_millis()
    );
    success_responses
}

async fn post_request(url: String, body: String) -> Result<(String, Response)> {
    let response = get_http_client()
        .post(get_rpc_url().join(&url).unwrap())
        .header(reqwest::header::ACCEPT, CONTENT_TYPE)
        .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
        .body(body)
        .send()
        .await?;
    Ok((url, response))
}

async fn get_request(url: String) -> Result<(String, Response)> {
    let response = get_http_client()
        .get(get_rpc_url().join(&url).unwrap())
        .header(reqwest::header::ACCEPT, CONTENT_TYPE)
        .send()
        .await?;
    Ok((url, response))
}

async fn get_sequence_number(account: AccountAddress) -> Result<(AccountAddress, U64)> {
    let url = format!("/v1/accounts/{}", account.to_standard_string());
    let (_, response) = get_request(url).await?;
    let sequence_number = response.json::<AccountData>().await?.sequence_number;

    Ok((account, sequence_number))
}

async fn post_simulate_request(
    body: SubmitTransactionRequest,
) -> Result<(SubmitTransactionRequest, Response)> {
    let json_body = serde_json::to_string(&body).unwrap();
    let (_, response) = post_request("/v1/transactions/simulate".to_string(), json_body).await?;

    Ok((body, response))
}

fn create_simulate_request(
    sender: Address,
    public_key: &str,
    sequence_number: U64,
) -> SubmitTransactionRequest {
    let dst = AccountAddress::from_str_strict(DESTINATION_ACCOUNT_ADDRESS).unwrap();
    let payload = aptos_api_types::TransactionPayload::EntryFunctionPayload(
        aptos_api_types::EntryFunctionPayload {
            function: EntryFunctionId::from_str("0x1::aptos_account::transfer").unwrap(),
            type_arguments: vec![],
            arguments: vec![
                serde_json::to_value(dst).unwrap(),   // to_address
                serde_json::to_value("100").unwrap(), // amount
            ],
        },
    );
    let user_transaction_request = UserTransactionRequestInner {
        sender,
        sequence_number,
        payload,
        max_gas_amount: 1_000u64.into(),
        gas_unit_price: 100u64.into(),
        expiration_timestamp_secs: (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300)
            .into(),
    };
    let signature = Ed25519Signature {
        public_key: HexEncodedBytes::from_str(public_key).unwrap(),
        // Zeroing out the signature
        signature: HexEncodedBytes::from_str("00".repeat(ED25519_SIGNATURE_LENGTH).as_str())
            .unwrap(),
    };
    SubmitTransactionRequest {
        user_transaction_request,
        signature: TransactionSignature::Ed25519Signature(signature),
    }
}

async fn get_account_resource_by_tag(
    resource_key: (AccountAddress, &'static str),
) -> Result<((AccountAddress, &'static str), Response)> {
    let url = format!(
        "/v1/accounts/{}/resource/{}",
        resource_key.0.to_standard_string(),
        urlencoding::encode(resource_key.1)
    );
    let (_, response) = get_request(url).await?;
    Ok((resource_key, response))
}
