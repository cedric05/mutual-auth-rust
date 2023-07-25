use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Message {
    pub msg: String,
    pub server_count: u8,
    pub client_count: u8,
}

impl Message {
    pub fn server_increment(&mut self) {
        self.server_count = self.server_count.checked_add(1).unwrap_or_default();
    }

    pub fn client_increment(&mut self) {
        self.client_count = self.client_count.checked_add(1).unwrap_or_default();
    }
}
