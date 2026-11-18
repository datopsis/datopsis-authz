//! S5 experimental supervisor. The helper is trusted host configuration, never client input.
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    collections::HashMap,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::Mutex,
};

type Slots = Arc<Mutex<HashMap<String, Arc<Mutex<Slot>>>>>;
#[derive(Default)]
struct Slot {
    name: Option<String>,
    active: usize,
    idle: Option<Instant>,
}
#[derive(Clone)]
pub struct Manager {
    helper: String,
    slots: Slots,
    timeout: Duration,
}
pub struct Lease {
    slot: Arc<Mutex<Slot>>,
    pub name: String,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let slot = self.slot.clone();
        tokio::spawn(async move {
            let mut slot = slot.lock().await;
            slot.active -= 1;
            slot.idle = Some(Instant::now());
        });
    }
}
impl Manager {
    pub fn configured() -> Result<Option<Self>> {
        let Ok(helper) = std::env::var("SAIL_LIFECYCLE_HELPER") else {
            return Ok(None);
        };
        ensure!(
            std::path::Path::new(&helper).is_absolute(),
            "absolute helper required"
        );
        let seconds: u64 = std::env::var("SAIL_IDLE_SECONDS")
            .unwrap_or("60".into())
            .parse()?;
        ensure!(seconds > 0, "positive idle timeout required");
        let this = Self {
            helper,
            slots: Arc::default(),
            timeout: Duration::from_secs(seconds),
        };
        let manager = this.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                // Keep map lock through reap to prevent creating two slots for one subject.
                let mut slots = manager.slots.lock().await;
                let subjects: Vec<_> = slots.keys().cloned().collect();
                for subject in subjects {
                    let mut slot = slots[&subject].lock().await;
                    if slot.active == 0 && slot.idle.is_some_and(|i| i.elapsed() >= manager.timeout)
                    {
                        if let Some(name) = &slot.name
                            && manager
                                .invoke(json!({"op":"stop", "name":name}))
                                .await
                                .is_err()
                        {
                            continue;
                        }
                        slot.name = None;
                        drop(slot);
                        slots.remove(&subject);
                    }
                }
            }
        });
        Ok(Some(this))
    }
    async fn invoke(&self, value: serde_json::Value) -> Result<serde_json::Value> {
        let mut child = Command::new(&self.helper)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        child
            .stdin
            .take()
            .context("helper stdin")?
            .write_all(&serde_json::to_vec(&value)?)
            .await?;
        let output =
            tokio::time::timeout(Duration::from_secs(90), child.wait_with_output()).await??;
        ensure!(output.status.success(), "lifecycle helper failed");
        Ok(serde_json::from_slice(&output.stdout)?)
    }
    pub async fn acquire(&self, subject: &str, token: &str) -> Result<Lease> {
        let mut slots = self.slots.lock().await;
        let slot = slots.entry(subject.to_owned()).or_default().clone();
        let mut state = slot.lock().await;
        drop(slots);
        let value = self
            .invoke(json!({"op":"ensure", "name":state.name, "token":token}))
            .await?;
        let name = value["name"].as_str().context("instance name")?.to_owned();
        ensure!(
            name.starts_with("s5-")
                && name.len() == 35
                && name[3..].bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid instance name"
        );
        state.name = Some(name.clone());
        state.active += 1;
        drop(state);
        Ok(Lease { slot, name })
    }
    pub fn connect(&self, lease: &Lease) -> Result<Child> {
        Ok(Command::new(&self.helper)
            .arg("relay")
            .arg(&lease.name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?)
    }
}
