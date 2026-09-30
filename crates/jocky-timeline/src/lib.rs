use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    UserLogin,
    FileCreated,
    FileModified,
    ProcessStarted,
    ProcessTerminated,
    NetworkConnection,
    ServiceStarted,
    DriverLoaded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub event_type: EventType,
    pub source: String,
    pub description: String,
    pub evidence_id: String,
}

pub struct TimelineBuilder {
    events: Vec<TimelineEvent>,
}

impl TimelineBuilder {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn add_event(&mut self, event: TimelineEvent) {
        self.events.push(event);
    }

    pub fn build(&self) -> Vec<TimelineEvent> {
        let mut list = self.events.clone();
        list.sort_by_key(|e| e.timestamp);
        list
    }
}
