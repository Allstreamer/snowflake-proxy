use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use webrtc::api::APIBuilder;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::api::interceptor_registry::register_default_interceptors;

const SESSION_ID_LENGTH: usize = 16;

fn generate_sid() -> String {
    let random_bytes: [u8; SESSION_ID_LENGTH] = rand::thread_rng().gen::<[u8; SESSION_ID_LENGTH]>();
    base64::encode(random_bytes).replace("==", "")
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct ProxyPollRequest {
    sid: String,
    version: String,
    #[serde(rename(serialize = "Type"))]
    proxy_type: String,
    #[serde(rename(serialize = "NAT"))]
    nat: String,
    clients: u64,
    accepted_relay_pattern: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let poll = ProxyPollRequest {
        sid: generate_sid(),
        version: String::from("1.3"),
        proxy_type: String::from("standalone"),
        nat: String::from("restricted"),
        clients: 0,
        accepted_relay_pattern: String::from("snowflake.torproject.net$"),
    };

    println!("{}", serde_json::to_string(&poll)?);

    let client = reqwest::Client::new();

    loop {
        let res = client
            .post("https://snowflake-broker.torproject.net/proxy")
            .timeout(Duration::from_secs(30))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&poll)?)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        println!("{:?}", res);

        println!("{:?}", serde_json::from_str::<serde_json::Value>(res.get("Offer").unwrap().get("sdp").unwrap().as_str().unwrap()));

        let mut registry = Registry::new();
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
    
        registry = register_default_interceptors(registry, &mut m)?;
        let api = APIBuilder::new().build();
    
        let config = RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: vec!["stun:stun.stunprotocol.org:3478".to_owned()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let peer_connection = api.new_peer_connection(config).await?;
    }


    Ok(())
}
