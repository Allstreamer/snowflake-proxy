use anyhow::{bail, Context, Result};
use base64::Engine;
use ip_utils::filter_local_from_sdp_offer;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{sync::Arc, time::Duration, net::IpAddr};
use tracing::{error, info, warn};
use webrtc::{
    api::{
        interceptor_registry::register_default_interceptors, media_engine::MediaEngine, APIBuilder,
    },
    data_channel::{data_channel_message::DataChannelMessage, RTCDataChannel},
    ice_transport::ice_server::RTCIceServer,
    interceptor::registry::Registry,
    peer_connection::{
        configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
        sdp::session_description::RTCSessionDescription,
    },
};
mod ip_utils;


macro_rules! here {
    () => {
        concat!("at ", file!(), " line ", line!(), " column ", column!())
    };
}

enum ProxyType {
    Standalone,
}

struct SnowFlakeProxy {
    capacity: u32,
    stun_url: String,
    broker_url: String,
    relay_url: String,
    nat_probe_url: String,
    keep_local_addresses: bool,
    nat_type_measurement_interval: Duration,
    proxy_type: ProxyType,
    relay_domain_name_pattern: String,
    allow_non_tls_relay: bool,
}

const SESSION_ID_LENGTH: usize = 16;
fn generate_sid() -> String {
    let random_bytes: [u8; SESSION_ID_LENGTH] = rand::thread_rng().gen::<[u8; SESSION_ID_LENGTH]>();
    let mut buf = String::new();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(random_bytes, &mut buf);
    buf
}

impl Default for SnowFlakeProxy {
    /// See https://github.com/keroserene/snowflake/blob/master/proxy/main.go for source of these values
    fn default() -> Self {
        Self {
            capacity: 0,
            stun_url: "stun:stun.l.google.com:19302".to_string(),
            broker_url: "https://snowflake-broker.torproject.net/".to_string(),
            relay_url: "wss://snowflake.bamsoftware.com/".to_string(),
            nat_probe_url: "https://snowflake-broker.torproject.net:8443/probe".to_string(),
            keep_local_addresses: false,
            nat_type_measurement_interval: Duration::from_secs(60 * 60 * 24), // 24 Hours
            proxy_type: ProxyType::Standalone,
            relay_domain_name_pattern: "snowflake.torproject.net$".to_string(),
            allow_non_tls_relay: false,
        }
    }
}

impl SnowFlakeProxy {
    pub async fn start(&self) -> Result<()> {
        info!("Starting...");

        if !SnowFlakeProxy::is_valid_relay_domain_pattern(&self.relay_domain_name_pattern) {
            error!(
                "{} is an invalid relay_domain_name_pattern!",
                self.relay_domain_name_pattern
            );
            bail!(
                "{} is an invalid relay_domain_name_pattern!",
                self.relay_domain_name_pattern
            );
        }

        let broker = Broker::new(self.broker_url.clone(), self.keep_local_addresses)?;
        let sid = generate_sid();
        loop {
            let offer = broker.find_offer(sid.clone()).await?;
            println!("{:?}", offer);
            if let Some(v) = broker.decode_offer(offer)? {
                self.setup_webrtc(v).await?;
            }
        }
    }

    fn is_valid_relay_domain_pattern(rule: &str) -> bool {
        return rule.ends_with("$");
    }

    async fn setup_webrtc(&self, offer_data: String) -> Result<()> {
        let config = RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: vec![self.stun_url.clone()],
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let registry = register_default_interceptors(Registry::new(), &mut m)?;

        let api = APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .build();

        let peer_connection = Arc::new(api.new_peer_connection(config).await?);
        let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);

        peer_connection.on_peer_connection_state_change(Box::new(
            move |s: RTCPeerConnectionState| {
                println!("Peer Connection State has changed: {s}");

                if s == RTCPeerConnectionState::Failed {
                    // Wait until PeerConnection has had no network activity for 30 seconds or another failure. It may be reconnected using an ICE Restart.
                    // Use webrtc.PeerConnectionStateDisconnected if you are interested in detecting faster timeout.
                    // Note that the PeerConnection may come back from PeerConnectionStateDisconnected.
                    println!("Peer Connection has gone to failed exiting");
                    let _ = done_tx.try_send(());
                }

                Box::pin(async {})
            },
        ));

        peer_connection
            .on_data_channel(Box::new(move |d: Arc<RTCDataChannel>| {
                let d_label = d.label().to_owned();
                let d_id = d.id();
                println!("New DataChannel {d_label} {d_id}");

                // Register channel opening handling
                Box::pin(async move {
                    let d2 = Arc::clone(&d);
                    let d_label2 = d_label.clone();
                    let d_id2 = d_id;
                    d.on_open(Box::new(move || {
                        println!("Data channel '{d_label2}'-'{d_id2}' open. Random messages will now be sent to any connected DataChannels every 5 seconds");

                        Box::pin(async move {
                            let mut result = Result::<usize>::Ok(0);
                            while result.is_ok() {
                                let timeout = tokio::time::sleep(Duration::from_secs(5));
                                tokio::pin!(timeout);

                                tokio::select! {
                                    _ = timeout.as_mut() =>{
                                        //let message = math_rand_alpha(15);
                                        println!("Uhhh idk'");
                                        //result = d2.send_text(message).await.map_err(Into::into);
                                    }
                                };
                            }
                        })
                    }));

                    // Register text message handling
                    d.on_message(Box::new(move |msg: DataChannelMessage| {
                        let msg_str = String::from_utf8(msg.data.to_vec()).unwrap();
                        println!("Message from DataChannel '{d_label}': '{msg_str}'");
                        Box::pin(async {})
                    }));
                })
            }));

        let offer = serde_json::from_str::<RTCSessionDescription>(&offer_data)?;
        peer_connection.set_remote_description(offer).await?;
        let answer = peer_connection.create_answer(None).await?;
        let mut gather_complete = peer_connection.gathering_complete_promise().await;
        peer_connection.set_local_description(answer).await?;
        let _ = gather_complete.recv().await;

        match peer_connection.local_description().await {
            Some(local_desc) => {
                filter_local_from_sdp_offer(&local_desc.sdp);
            },
            None => {
                warn!("generate local_description failed! {}", here!());
                bail!("generate local_description failed! {}", here!());
            }
        }

        Ok(())
    }
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

struct Broker {
    broker_url: String,
    transport: reqwest::Client,
    keep_local_address: bool,
}

impl Broker {
    pub fn new(broker_url: String, keep_local_address: bool) -> Result<Self> {
        let transport = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            broker_url,
            transport,
            keep_local_address,
        })
    }

    pub async fn find_offer(&self, sid: String) -> Result<serde_json::Value> {
        let poll = ProxyPollRequest {
            sid,
            version: String::from("1.3"),
            proxy_type: String::from("standalone"), // TODO: Find actual Proxy Type
            nat: String::from("restricted"),        // TODO: Find actual nat Type
            clients: 0,
            accepted_relay_pattern: String::from("snowflake.torproject.net$"),
        };

        let mut res = self
            .transport
            .post(format!("{}{}", self.broker_url, "proxy"))
            .timeout(Duration::from_secs(30)) // Investigate timeout
            .header("content-type", "application/json")
            .body(serde_json::to_string(&poll).context(here!())?)
            .send()
            .await
            .context(here!())?;
        res = res.error_for_status().context(here!())?;
        Ok(res.json::<serde_json::Value>().await.context(here!())?)
    }

    pub fn decode_offer(&self, offer: Value) -> Result<Option<String>> {
        if offer["Status"].as_str() != Some("client match") {
            info!("Decoded offer, {:?}.", offer["Status"].as_str());
            return Ok(None);
        }

        /* TODO: Workout better System
        match offer["RelayURL"].as_str() {
            Some(v) => {
                if Url::parse(v)?.domain() != Some("snowflake.torproject.net") {
                    warn!(
                        "Attemptted Connection with following RelayURL: {:?}. REJECTED!",
                        offer["RelayURL"].as_str()
                    );
                    return Ok(None);
                }
            }
            None => {
                warn!(
                    "Attemptted Connection with following RelayURL: {:?}. REJECTED!",
                    offer["RelayURL"].as_str()
                );
                return Ok(None);
            }
        }
         */

        let offer = offer["Offer"].as_str();
        match offer {
            Some(v) => {
                if v.is_empty() {
                    return Ok(None);
                }
                Ok(Some(v.to_owned()))
            }
            None => return Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let proxy = SnowFlakeProxy {
        ..Default::default()
    };

    proxy.start().await?;

    Ok(())
}
