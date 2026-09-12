use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use crate::model::{Contact, ConversationSummary, MessageRecord};
use crate::protocol::ECHO_SERVICE_PEER_ID;
use crate::EchoMeshError;

pub struct StorageManager {
    conn: Mutex<Connection>,
}

impl StorageManager {
    /// Opens or creates SQLite database at `path`, runs migrations and seeds default contacts.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, EchoMeshError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let conn = Connection::open(path)
            .map_err(|e| EchoMeshError::StorageError(format!("Failed to open SQLite database: {}", e)))?;

        // Optimization pragmas
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed executing pragmas: {}", e)))?;

        // Migration: create tables and indices
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contacts (
                peer_id BLOB PRIMARY KEY,
                name TEXT NOT NULL,
                added_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_peer_id BLOB NOT NULL,
                sender_peer_id BLOB NOT NULL,
                text TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                is_outgoing INTEGER NOT NULL,
                status INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conv_time 
                ON messages(conversation_peer_id, timestamp ASC);

            CREATE INDEX IF NOT EXISTS idx_messages_unread 
                ON messages(conversation_peer_id, is_outgoing, status);",
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed creating schema: {}", e)))?;

        // Seed default Echo Relay Node contact ([0xEE; 32]) if not already present
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        conn.execute(
            "INSERT OR IGNORE INTO contacts (peer_id, name, added_at)
             VALUES (?1, 'Echo Relay Node', ?2);",
            params![&ECHO_SERVICE_PEER_ID[..], now_millis],
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed seeding Echo Relay Node: {}", e)))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Creates an in-memory database instance (ideal for unit tests).
    pub fn new_in_memory() -> Result<Self, EchoMeshError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| EchoMeshError::StorageError(format!("Failed to open in-memory SQLite: {}", e)))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contacts (
                peer_id BLOB PRIMARY KEY,
                name TEXT NOT NULL,
                added_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_peer_id BLOB NOT NULL,
                sender_peer_id BLOB NOT NULL,
                text TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                is_outgoing INTEGER NOT NULL,
                status INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conv_time 
                ON messages(conversation_peer_id, timestamp ASC);

            CREATE INDEX IF NOT EXISTS idx_messages_unread 
                ON messages(conversation_peer_id, is_outgoing, status);",
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed creating schema: {}", e)))?;

        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        conn.execute(
            "INSERT OR IGNORE INTO contacts (peer_id, name, added_at)
             VALUES (?1, 'Echo Relay Node', ?2);",
            params![&ECHO_SERVICE_PEER_ID[..], now_millis],
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed seeding Echo Relay Node: {}", e)))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn save_contact(&self, contact: &Contact) -> Result<(), EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO contacts (peer_id, name, added_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(peer_id) DO UPDATE SET name=excluded.name;",
            params![&contact.peer_id, &contact.name, contact.added_at as i64],
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed saving contact: {}", e)))?;
        Ok(())
    }

    pub fn get_contacts(&self) -> Result<Vec<Contact>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT peer_id, name, added_at FROM contacts ORDER BY added_at ASC")
            .map_err(|e| EchoMeshError::StorageError(format!("Prepare failed: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                let peer_id: Vec<u8> = row.get(0)?;
                let name: String = row.get(1)?;
                let added_at_i64: i64 = row.get(2)?;
                Ok(Contact {
                    peer_id,
                    name,
                    added_at: added_at_i64 as u64,
                })
            })
            .map_err(|e| EchoMeshError::StorageError(format!("Query failed: {}", e)))?;

        let mut contacts = Vec::new();
        for item in rows {
            contacts.push(item.map_err(|e| EchoMeshError::StorageError(e.to_string()))?);
        }
        Ok(contacts)
    }

    pub fn get_contact_by_peer_id(&self, peer_id: &[u8]) -> Result<Option<Contact>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT peer_id, name, added_at FROM contacts WHERE peer_id = ?1")
            .map_err(|e| EchoMeshError::StorageError(format!("Prepare failed: {}", e)))?;

        let contact = stmt
            .query_row(params![peer_id], |row| {
                let peer_id: Vec<u8> = row.get(0)?;
                let name: String = row.get(1)?;
                let added_at_i64: i64 = row.get(2)?;
                Ok(Contact {
                    peer_id,
                    name,
                    added_at: added_at_i64 as u64,
                })
            })
            .optional()
            .map_err(|e| EchoMeshError::StorageError(format!("Query failed: {}", e)))?;

        Ok(contact)
    }

    pub fn save_message(&self, msg: &MessageRecord) -> Result<(), EchoMeshError> {
        let conn = self.conn.lock().unwrap();

        // Ensure contact entry exists for this conversation
        let now_millis = msg.timestamp as i64;
        let mut default_name = format!(
            "0x{}...",
            hex::encode(&msg.conversation_peer_id[..4.min(msg.conversation_peer_id.len())])
        );
        if msg.conversation_peer_id == ECHO_SERVICE_PEER_ID {
            default_name = "Echo Relay Node".to_string();
        }

        conn.execute(
            "INSERT OR IGNORE INTO contacts (peer_id, name, added_at)
             VALUES (?1, ?2, ?3);",
            params![&msg.conversation_peer_id, default_name, now_millis],
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed ensuring contact: {}", e)))?;

        conn.execute(
            "INSERT INTO messages (id, conversation_peer_id, sender_peer_id, text, timestamp, is_outgoing, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET status=excluded.status, text=excluded.text;",
            params![
                &msg.id,
                &msg.conversation_peer_id,
                &msg.sender_peer_id,
                &msg.text,
                msg.timestamp as i64,
                if msg.is_outgoing { 1i64 } else { 0i64 },
                msg.status as i64,
            ],
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed saving message: {}", e)))?;
        Ok(())
    }

    pub fn update_message_status(&self, id: &str, status: u8) -> Result<(), EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE messages SET status = ?1 WHERE id = ?2;",
            params![status as i64, id],
        )
        .map_err(|e| EchoMeshError::StorageError(format!("Failed updating message status: {}", e)))?;
        Ok(())
    }

    pub fn get_messages(
        &self,
        peer_id: &[u8],
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MessageRecord>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, conversation_peer_id, sender_peer_id, text, timestamp, is_outgoing, status
                 FROM messages
                 WHERE conversation_peer_id = ?1
                 ORDER BY timestamp ASC
                 LIMIT ?2 OFFSET ?3;",
            )
            .map_err(|e| EchoMeshError::StorageError(format!("Prepare failed: {}", e)))?;

        let rows = stmt
            .query_map(params![peer_id, limit as i64, offset as i64], |row| {
                let id: String = row.get(0)?;
                let conversation_peer_id: Vec<u8> = row.get(1)?;
                let sender_peer_id: Vec<u8> = row.get(2)?;
                let text: String = row.get(3)?;
                let timestamp_i64: i64 = row.get(4)?;
                let is_outgoing_i64: i64 = row.get(5)?;
                let status_i64: i64 = row.get(6)?;

                Ok(MessageRecord {
                    id,
                    conversation_peer_id,
                    sender_peer_id,
                    text,
                    timestamp: timestamp_i64 as u64,
                    is_outgoing: is_outgoing_i64 != 0,
                    status: status_i64 as u8,
                })
            })
            .map_err(|e| EchoMeshError::StorageError(format!("Query failed: {}", e)))?;

        let mut messages = Vec::new();
        for item in rows {
            messages.push(item.map_err(|e| EchoMeshError::StorageError(e.to_string()))?);
        }
        Ok(messages)
    }

    pub fn get_conversations(&self) -> Result<Vec<ConversationSummary>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT 
                    c.peer_id,
                    c.name,
                    (SELECT text FROM messages WHERE conversation_peer_id = c.peer_id ORDER BY timestamp DESC LIMIT 1) AS last_msg,
                    COALESCE((SELECT timestamp FROM messages WHERE conversation_peer_id = c.peer_id ORDER BY timestamp DESC LIMIT 1), c.added_at) AS last_ts,
                    (SELECT COUNT(*) FROM messages WHERE conversation_peer_id = c.peer_id AND is_outgoing = 0 AND status = 0) AS unread
                 FROM contacts c
                 ORDER BY last_ts DESC;",
            )
            .map_err(|e| EchoMeshError::StorageError(format!("Prepare failed: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                let peer_id: Vec<u8> = row.get(0)?;
                let title: String = row.get(1)?;
                let last_message: Option<String> = row.get(2)?;
                let last_timestamp_i64: i64 = row.get(3)?;
                let unread_count_i64: i64 = row.get(4)?;

                Ok(ConversationSummary {
                    peer_id,
                    title,
                    last_message,
                    last_timestamp: last_timestamp_i64 as u64,
                    unread_count: unread_count_i64 as u32,
                })
            })
            .map_err(|e| EchoMeshError::StorageError(format!("Query failed: {}", e)))?;

        let mut convs = Vec::new();
        for item in rows {
            convs.push(item.map_err(|e| EchoMeshError::StorageError(e.to_string()))?);
        }
        Ok(convs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_init_seeds_echo_node() {
        let storage = StorageManager::new_in_memory().expect("in memory init");
        let contacts = storage.get_contacts().expect("get contacts");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].name, "Echo Relay Node");
        assert_eq!(contacts[0].peer_id, ECHO_SERVICE_PEER_ID.to_vec());
    }

    #[test]
    fn test_save_and_retrieve_contact() {
        let storage = StorageManager::new_in_memory().expect("in memory init");
        let peer_alice = [0xAA; 32];
        let contact = Contact {
            peer_id: peer_alice.to_vec(),
            name: "Alice".to_string(),
            added_at: 1000,
        };
        storage.save_contact(&contact).expect("save contact");

        let contacts = storage.get_contacts().expect("get contacts");
        assert_eq!(contacts.len(), 2); // Echo Relay Node + Alice
        let retrieved = storage.get_contact_by_peer_id(&peer_alice).expect("get by id");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Alice");
    }

    #[test]
    fn test_save_and_retrieve_messages_and_conversations() {
        let storage = StorageManager::new_in_memory().expect("in memory init");
        let peer_bob = [0xBB; 32];

        let msg1 = MessageRecord {
            id: "msg_1".to_string(),
            conversation_peer_id: peer_bob.to_vec(),
            sender_peer_id: peer_bob.to_vec(),
            text: "Hello from Bob".to_string(),
            timestamp: 1000,
            is_outgoing: false,
            status: 0,
        };
        storage.save_message(&msg1).expect("save msg1");

        let msg2 = MessageRecord {
            id: "msg_2".to_string(),
            conversation_peer_id: peer_bob.to_vec(),
            sender_peer_id: vec![0xCC; 32],
            text: "Reply to Bob".to_string(),
            timestamp: 2000,
            is_outgoing: true,
            status: 1,
        };
        storage.save_message(&msg2).expect("save msg2");

        let messages = storage.get_messages(&peer_bob, 10, 0).expect("get messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].text, "Hello from Bob");
        assert_eq!(messages[1].text, "Reply to Bob");

        let convs = storage.get_conversations().expect("get conversations");
        let bob_conv = convs.iter().find(|c| c.peer_id == peer_bob.to_vec()).expect("bob conv exists");
        assert_eq!(bob_conv.last_message, Some("Reply to Bob".to_string()));
        assert_eq!(bob_conv.last_timestamp, 2000);
        assert_eq!(bob_conv.unread_count, 1); // msg1 was incoming with status 0
    }
}
