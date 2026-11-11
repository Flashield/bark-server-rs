//! The event bus (ADR-0001): the transport-agnostic in-process seam between
//! the push pipeline and the realtime transports. APNs delivery stays on its
//! unchanged path in the push core; the SSE endpoint (ticket 07's
//! [`crate::api::sse`]) subscribes here, and the WebSocket endpoint reserved
//! by ADR-0001 would subscribe to the same bus without touching delivery
//! semantics.
//!
//! # Shape
//!
//! One broadcast channel per Device Key (created lazily, kept for the
//! process lifetime — one entry per Device ever streamed to), each carrying
//! `Arc<PushEvent>` values. Every subscriber gets the events published after
//! its subscription: live delivery only. Replay of missed messages is
//! ticket 08's store-backed half of ADR-0002; this bus is the live half.
//!
//! # Per-device FIFO ordering
//!
//! The publish path serializes per Device: the (assign monotonic id →
//! persist → broadcast) sequence for one Device runs under that Device's
//! lock, so concurrent pushes to the same Device persist and fan out in
//! monotonic id order and every stream observes exactly that order. Devices
//! are independent — publishes to different Devices never block each other.
//!
//! # Lag policy
//!
//! Channels are bounded: a subscriber that falls more than
//! [`CHANNEL_CAPACITY`] events behind is reported `Lagged` by the channel.
//! The SSE endpoint treats lag as a terminal condition for that stream
//! (at-least-once semantics: the client reconnects with `Last-Event-ID`,
//! which ticket 08 answers from the message store).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::{Map, Value};
use tokio::sync::broadcast;

use crate::apns::PushMessage;
use crate::store::{MessageRecord, NewMessage, Store, StoreError};

/// Broadcast buffer per Device: a live stream may fall this many events
/// behind before the channel reports it `Lagged`.
const CHANNEL_CAPACITY: usize = 256;

/// One Push as fanned out on the bus: the persisted record's fields, carried
/// as JSON to every subscriber. The JSON body of an SSE event is exactly
/// this struct serialized (field order = declaration order), so the wire
/// contract is: `id` (per-device monotonic message id, also the SSE `id:`
/// line), `title`, `subtitle`, `body`, `ext_params` (Ext Params object),
/// `device_key`, `created_at` (unix seconds). This is the "full Push" of the
/// spec's story 21 — the user-supplied `id`/`group`/… parameters ride inside
/// `ext_params`, `sound` remains an APNs-payload concern.
#[derive(Debug, Clone, Serialize)]
pub struct PushEvent {
    pub id: i64,
    pub title: String,
    pub subtitle: String,
    pub body: String,
    pub ext_params: Map<String, Value>,
    pub device_key: String,
    pub created_at: i64,
}

impl PushEvent {
    fn from_record(record: &MessageRecord, ext_params: Map<String, Value>) -> Self {
        Self {
            id: record.id,
            title: record.title.clone(),
            subtitle: record.subtitle.clone(),
            body: record.body.clone(),
            ext_params,
            device_key: record.device_key.clone(),
            created_at: record.created_at,
        }
    }
}

/// Per-Device channel entry: the broadcast sender plus the publish lock that
/// serializes id assignment → persist → send for this Device.
struct DeviceChannel {
    sender: broadcast::Sender<Arc<PushEvent>>,
    publish_lock: Arc<tokio::sync::Mutex<()>>,
}

/// The in-process event bus. Cheap to share ([`Arc`] in [`crate::server::AppState`]).
pub struct EventBus {
    store: Arc<dyn Store>,
    devices: Mutex<HashMap<String, DeviceChannel>>,
}

impl EventBus {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self {
            store,
            devices: Mutex::new(HashMap::new()),
        }
    }

    /// The Device's channel, created on first use.
    fn channel(&self, device_key: &str) -> DeviceChannelHandle {
        let mut devices = self.devices.lock().unwrap_or_else(|p| p.into_inner());
        match devices.get(device_key) {
            Some(entry) => DeviceChannelHandle {
                sender: entry.sender.clone(),
                lock: entry.publish_lock.clone(),
            },
            None => {
                let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
                let entry = DeviceChannel {
                    sender: sender.clone(),
                    publish_lock: Arc::new(tokio::sync::Mutex::new(())),
                };
                devices.insert(device_key.to_string(), entry);
                DeviceChannelHandle {
                    sender,
                    lock: devices[device_key].publish_lock.clone(),
                }
            }
        }
    }

    /// Persist the Push to the per-device message store, then broadcast it
    /// to every live subscriber of that Device — both under the Device's
    /// publish lock, so fan-out order equals monotonic id order. Returns the
    /// persisted record. Delivering to zero subscribers is fine (the Push is
    /// still persisted — store-and-forward, ADR-0002).
    pub async fn publish(&self, push: &PushMessage) -> Result<MessageRecord, StoreError> {
        let channel = self.channel(&push.device_key);
        let _guard = channel.lock.lock().await;
        let record = self.store.insert_message(&NewMessage {
            device_key: push.device_key.clone(),
            title: push.title.clone(),
            subtitle: push.subtitle.clone(),
            body: push.body.clone(),
            ext_params: serde_json::to_string(&push.ext_params)
                .expect("ext params serialize to JSON"),
        })?;
        let ext_params: Map<String, Value> =
            serde_json::from_str(&record.ext_params).expect("stored ext params are valid JSON");
        // A broadcast with no receivers is the no-streams-connected case.
        let _ = channel
            .sender
            .send(Arc::new(PushEvent::from_record(&record, ext_params)));
        Ok(record)
    }

    /// Subscribe to a Device's live push events (the SSE stream's receiver;
    /// the future WS endpoint's too). Events published before this call are
    /// not delivered — replay is ticket 08's job.
    pub fn subscribe(&self, device_key: &str) -> broadcast::Receiver<Arc<PushEvent>> {
        self.channel(device_key).sender.subscribe()
    }

    /// Live Realtime Streams across all Devices — the sum of current
    /// receivers; backs `/info`'s `active_streams`.
    pub fn active_streams(&self) -> usize {
        self.devices
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|entry| entry.sender.receiver_count())
            .sum()
    }
}

/// The pieces of a [`DeviceChannel`] a caller needs, cloned out from under
/// the registry lock (never hold a std lock across `.await`).
struct DeviceChannelHandle {
    sender: broadcast::Sender<Arc<PushEvent>>,
    lock: Arc<tokio::sync::Mutex<()>>,
}
