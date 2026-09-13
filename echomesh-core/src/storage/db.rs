use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{Contact, ConversationSummary, MessageRecord};
use crate::protocol::ECHO_SERVICE_PEER_ID;
use crate::EchoMeshError;

const ENC_PREFIX: &str = "enc1:";

pub struct StorageManager {
    conn: Mutex<Connection>,
    key: [u8; 32],
}

impl StorageManager {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, EchoMeshError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(storage_err)?; }
        let key_path = path.parent().unwrap_or_else(|| Path::new(".")).join("storage.key");
        let key = load_or_generate_key(&key_path)?;
        let conn = Connection::open(path).map_err(storage_err)?;
        let manager = Self { conn: Mutex::new(conn), key };
        manager.initialize()?;
        Ok(manager)
    }

    pub fn new_in_memory() -> Result<Self, EchoMeshError> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let conn = Connection::open_in_memory().map_err(storage_err)?;
        let manager = Self { conn: Mutex::new(conn), key };
        manager.initialize()?;
        Ok(manager)
    }

    fn initialize(&self) -> Result<(), EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS contacts (
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
             CREATE INDEX IF NOT EXISTS idx_messages_conv_time ON messages(conversation_peer_id, timestamp ASC);
             CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(conversation_peer_id, is_outgoing, status);"
        ).map_err(storage_err)?;
        let now = now_millis() as i64;
        let echo_name = encrypt_string(&self.key, "Echo Relay Node")?;
        conn.execute(
            "INSERT OR IGNORE INTO contacts (peer_id, name, added_at) VALUES (?1, ?2, ?3)",
            params![&ECHO_SERVICE_PEER_ID[..], echo_name, now],
        ).map_err(storage_err)?;
        Ok(())
    }

    pub fn save_contact(&self, contact: &Contact) -> Result<(), EchoMeshError> {
        let name = encrypt_string(&self.key, &contact.name)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO contacts (peer_id, name, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(peer_id) DO UPDATE SET name=excluded.name",
            params![&contact.peer_id, name, contact.added_at as i64],
        ).map_err(storage_err)?;
        Ok(())
    }

    pub fn get_contacts(&self) -> Result<Vec<Contact>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT peer_id, name, added_at FROM contacts ORDER BY added_at ASC").map_err(storage_err)?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))).map_err(storage_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (peer_id, stored_name, added_at) = row.map_err(storage_err)?;
            out.push(Contact { peer_id, name: decrypt_string(&self.key, &stored_name)?, added_at: added_at as u64 });
        }
        Ok(out)
    }

    pub fn get_contact_by_peer_id(&self, peer_id: &[u8]) -> Result<Option<Contact>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(Vec<u8>, String, i64)> = conn.query_row(
            "SELECT peer_id, name, added_at FROM contacts WHERE peer_id=?1",
            params![peer_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional().map_err(storage_err)?;
        row.map(|(id, name, added_at)| Ok(Contact { peer_id: id, name: decrypt_string(&self.key, &name)?, added_at: added_at as u64 })).transpose()
    }

    pub fn save_message(&self, msg: &MessageRecord) -> Result<(), EchoMeshError> {
        let text = encrypt_string(&self.key, &msg.text)?;
        let default_name = if msg.conversation_peer_id == ECHO_SERVICE_PEER_ID {
            "Echo Relay Node".to_string()
        } else {
            format!("0x{}...", hex::encode(&msg.conversation_peer_id[..4.min(msg.conversation_peer_id.len())]))
        };
        let encrypted_name = encrypt_string(&self.key, &default_name)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO contacts (peer_id, name, added_at) VALUES (?1, ?2, ?3)",
            params![&msg.conversation_peer_id, encrypted_name, msg.timestamp as i64],
        ).map_err(storage_err)?;
        conn.execute(
            "INSERT INTO messages (id, conversation_peer_id, sender_peer_id, text, timestamp, is_outgoing, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET status=excluded.status, text=excluded.text",
            params![&msg.id, &msg.conversation_peer_id, &msg.sender_peer_id, text, msg.timestamp as i64, if msg.is_outgoing {1i64} else {0i64}, msg.status as i64],
        ).map_err(storage_err)?;
        Ok(())
    }

    pub fn update_message_status(&self, id: &str, status: u8) -> Result<(), EchoMeshError> {
        self.conn.lock().unwrap().execute("UPDATE messages SET status=?1 WHERE id=?2", params![status as i64, id]).map_err(storage_err)?;
        Ok(())
    }

    pub fn get_messages(&self, peer_id: &[u8], limit: usize, offset: usize) -> Result<Vec<MessageRecord>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, conversation_peer_id, sender_peer_id, text, timestamp, is_outgoing, status
             FROM messages WHERE conversation_peer_id=?1 ORDER BY timestamp ASC LIMIT ?2 OFFSET ?3"
        ).map_err(storage_err)?;
        let rows = stmt.query_map(params![peer_id, limit as i64, offset as i64], |r| Ok((
            r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?
        ))).map_err(storage_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, conversation_peer_id, sender_peer_id, stored_text, timestamp, is_outgoing, status) = row.map_err(storage_err)?;
            out.push(MessageRecord { id, conversation_peer_id, sender_peer_id, text: decrypt_string(&self.key, &stored_text)?, timestamp: timestamp as u64, is_outgoing: is_outgoing != 0, status: status as u8 });
        }
        Ok(out)
    }

    pub fn get_conversations(&self) -> Result<Vec<ConversationSummary>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.peer_id, c.name,
             (SELECT text FROM messages WHERE conversation_peer_id=c.peer_id ORDER BY timestamp DESC LIMIT 1),
             COALESCE((SELECT timestamp FROM messages WHERE conversation_peer_id=c.peer_id ORDER BY timestamp DESC LIMIT 1), c.added_at),
             (SELECT COUNT(*) FROM messages WHERE conversation_peer_id=c.peer_id AND is_outgoing=0 AND status=0)
             FROM contacts c ORDER BY 4 DESC"
        ).map_err(storage_err)?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?))).map_err(storage_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (peer_id, title, last, last_ts, unread) = row.map_err(storage_err)?;
            out.push(ConversationSummary {
                peer_id,
                title: decrypt_string(&self.key, &title)?,
                last_message: last.map(|v| decrypt_string(&self.key, &v)).transpose()?,
                last_timestamp: last_ts as u64,
                unread_count: unread as u32,
            });
        }
        Ok(out)
    }
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn storage_err<E: std::fmt::Display>(e: E) -> EchoMeshError { EchoMeshError::StorageError(e.to_string()) }

fn load_or_generate_key(path: &PathBuf) -> Result<[u8; 32], EchoMeshError> {
    if path.exists() {
        let bytes = std::fs::read(path).map_err(storage_err)?;
        return bytes.as_slice().try_into().map_err(|_| EchoMeshError::StorageError("invalid storage.key length".into()));
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    #[cfg(unix)] {
        use std::fs::OpenOptions; use std::io::Write; use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).map_err(storage_err)?;
        f.write_all(&key).map_err(storage_err)?;
    }
    #[cfg(not(unix))] { std::fs::write(path, key).map_err(storage_err)?; }
    Ok(key)
}

fn encrypt_string(key: &[u8; 32], value: &str) -> Result<String, EchoMeshError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(storage_err)?;
    let mut nonce = [0u8; 24]; OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), value.as_bytes()).map_err(storage_err)?;
    let mut packed = nonce.to_vec(); packed.extend_from_slice(&ciphertext);
    Ok(format!("{}{}", ENC_PREFIX, base64::engine::general_purpose::STANDARD.encode(packed)))
}

fn decrypt_string(key: &[u8; 32], value: &str) -> Result<String, EchoMeshError> {
    if !value.starts_with(ENC_PREFIX) { return Ok(value.to_string()); }
    let packed = base64::engine::general_purpose::STANDARD.decode(&value[ENC_PREFIX.len()..]).map_err(storage_err)?;
    if packed.len() < 25 { return Err(EchoMeshError::StorageError("truncated encrypted value".into())); }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(storage_err)?;
    let plain = cipher.decrypt(XNonce::from_slice(&packed[..24]), &packed[24..]).map_err(storage_err)?;
    String::from_utf8(plain).map_err(storage_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_storage_roundtrip() {
        let storage = StorageManager::new_in_memory().unwrap();
        let peer = [0xAA; 32];
        storage.save_contact(&Contact { peer_id: peer.to_vec(), name: "Alice".into(), added_at: 1 }).unwrap();
        assert_eq!(storage.get_contact_by_peer_id(&peer).unwrap().unwrap().name, "Alice");
        let msg = MessageRecord { id: "1".into(), conversation_peer_id: peer.to_vec(), sender_peer_id: peer.to_vec(), text: "secret message".into(), timestamp: 2, is_outgoing: false, status: 1 };
        storage.save_message(&msg).unwrap();
        assert_eq!(storage.get_messages(&peer, 10, 0).unwrap()[0].text, "secret message");
    }
}
