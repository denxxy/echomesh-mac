use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{Contact, ConversationSummary, MessageRecord};
use crate::protocol::ECHO_SERVICE_PEER_ID;
use crate::EchoMeshError;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

pub struct StorageManager {
    conn: Mutex<Connection>,
}

impl StorageManager {
    pub fn new_encrypted<P: AsRef<Path>>(path: P, key: &[u8; 32]) -> Result<Self, EchoMeshError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| EchoMeshError::StorageError(format!("create db directory: {e}")))?;
        }
        if is_plaintext_sqlite(path)? {
            migrate_plaintext_database(path, key)?;
        }
        let conn = Connection::open(path)
            .map_err(|e| EchoMeshError::StorageError(format!("open encrypted database: {e}")))?;
        apply_sqlcipher_key(&conn, key)?;
        verify_sqlcipher(&conn)?;
        initialize_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn new_in_memory() -> Result<Self, EchoMeshError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| EchoMeshError::StorageError(format!("open in-memory database: {e}")))?;
        initialize_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn save_contact(&self, contact: &Contact) -> Result<(), EchoMeshError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO contacts (peer_id, name, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(peer_id) DO UPDATE SET name=excluded.name",
            params![&contact.peer_id, &contact.name, contact.added_at as i64],
        ).map_err(storage_err("save contact"))?;
        Ok(())
    }

    pub fn get_contacts(&self) -> Result<Vec<Contact>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT peer_id, name, added_at FROM contacts ORDER BY added_at ASC")
            .map_err(storage_err("prepare contacts"))?;
        let rows = stmt.query_map([], |row| Ok(Contact {
            peer_id: row.get(0)?, name: row.get(1)?, added_at: row.get::<_, i64>(2)? as u64,
        })).map_err(storage_err("query contacts"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_err("read contacts"))
    }

    pub fn get_contact_by_peer_id(&self, peer_id: &[u8]) -> Result<Option<Contact>, EchoMeshError> {
        self.conn.lock().unwrap().query_row(
            "SELECT peer_id, name, added_at FROM contacts WHERE peer_id = ?1",
            params![peer_id],
            |row| Ok(Contact { peer_id: row.get(0)?, name: row.get(1)?, added_at: row.get::<_, i64>(2)? as u64 }),
        ).optional().map_err(storage_err("get contact"))
    }

    pub fn save_message(&self, msg: &MessageRecord) -> Result<(), EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let name = if msg.conversation_peer_id == ECHO_SERVICE_PEER_ID {
            "Echo Relay Node".to_string()
        } else {
            "Encrypted Contact".to_string()
        };
        conn.execute(
            "INSERT OR IGNORE INTO contacts (peer_id, name, added_at) VALUES (?1, ?2, ?3)",
            params![&msg.conversation_peer_id, name, msg.timestamp as i64],
        ).map_err(storage_err("ensure contact"))?;
        conn.execute(
            "INSERT INTO messages (id, conversation_peer_id, sender_peer_id, text, timestamp, is_outgoing, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET status=excluded.status, text=excluded.text",
            params![&msg.id, &msg.conversation_peer_id, &msg.sender_peer_id, &msg.text,
                    msg.timestamp as i64, i64::from(msg.is_outgoing), msg.status as i64],
        ).map_err(storage_err("save message"))?;
        Ok(())
    }

    pub fn update_message_status(&self, id: &str, status: u8) -> Result<(), EchoMeshError> {
        self.conn.lock().unwrap().execute(
            "UPDATE messages SET status = ?1 WHERE id = ?2", params![status as i64, id],
        ).map_err(storage_err("update message status"))?;
        Ok(())
    }

    pub fn get_messages(&self, peer_id: &[u8], limit: usize, offset: usize) -> Result<Vec<MessageRecord>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, conversation_peer_id, sender_peer_id, text, timestamp, is_outgoing, status
             FROM messages WHERE conversation_peer_id = ?1 ORDER BY timestamp ASC LIMIT ?2 OFFSET ?3",
        ).map_err(storage_err("prepare messages"))?;
        let rows = stmt.query_map(params![peer_id, limit as i64, offset as i64], |row| Ok(MessageRecord {
            id: row.get(0)?, conversation_peer_id: row.get(1)?, sender_peer_id: row.get(2)?, text: row.get(3)?,
            timestamp: row.get::<_, i64>(4)? as u64, is_outgoing: row.get::<_, i64>(5)? != 0,
            status: row.get::<_, i64>(6)? as u8,
        })).map_err(storage_err("query messages"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_err("read messages"))
    }

    pub fn get_conversations(&self) -> Result<Vec<ConversationSummary>, EchoMeshError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.peer_id, c.name,
                (SELECT text FROM messages WHERE conversation_peer_id=c.peer_id ORDER BY timestamp DESC LIMIT 1),
                COALESCE((SELECT timestamp FROM messages WHERE conversation_peer_id=c.peer_id ORDER BY timestamp DESC LIMIT 1), c.added_at),
                (SELECT COUNT(*) FROM messages WHERE conversation_peer_id=c.peer_id AND is_outgoing=0 AND status=0)
             FROM contacts c ORDER BY 4 DESC",
        ).map_err(storage_err("prepare conversations"))?;
        let rows = stmt.query_map([], |row| Ok(ConversationSummary {
            peer_id: row.get(0)?, title: row.get(1)?, last_message: row.get(2)?,
            last_timestamp: row.get::<_, i64>(3)? as u64, unread_count: row.get::<_, i64>(4)? as u32,
        })).map_err(storage_err("query conversations"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_err("read conversations"))
    }
}

fn initialize_schema(conn: &Connection) -> Result<(), EchoMeshError> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS contacts (peer_id BLOB PRIMARY KEY, name TEXT NOT NULL, added_at INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS messages (
             id TEXT PRIMARY KEY, conversation_peer_id BLOB NOT NULL, sender_peer_id BLOB NOT NULL,
             text TEXT NOT NULL, timestamp INTEGER NOT NULL, is_outgoing INTEGER NOT NULL, status INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_messages_conv_time ON messages(conversation_peer_id, timestamp ASC);
         CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(conversation_peer_id, is_outgoing, status);",
    ).map_err(storage_err("initialize schema"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
    conn.execute(
        "INSERT OR IGNORE INTO contacts (peer_id, name, added_at) VALUES (?1, 'Echo Relay Node', ?2)",
        params![&ECHO_SERVICE_PEER_ID[..], now],
    ).map_err(storage_err("seed echo contact"))?;
    Ok(())
}

fn apply_sqlcipher_key(conn: &Connection, key: &[u8; 32]) -> Result<(), EchoMeshError> {
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))
        .map_err(storage_err("apply SQLCipher key"))
}

fn verify_sqlcipher(conn: &Connection) -> Result<(), EchoMeshError> {
    let version: String = conn.query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(storage_err("verify SQLCipher availability"))?;
    if version.trim().is_empty() {
        return Err(EchoMeshError::StorageError("SQLCipher support is unavailable".to_string()));
    }
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(storage_err("verify encrypted database key"))?;
    Ok(())
}

fn is_plaintext_sqlite(path: &Path) -> Result<bool, EchoMeshError> {
    if !path.exists() { return Ok(false); }
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|e| EchoMeshError::StorageError(format!("inspect database: {e}")))?;
    let mut header = [0u8; 16];
    let read = file.read(&mut header)
        .map_err(|e| EchoMeshError::StorageError(format!("read database header: {e}")))?;
    Ok(read == 16 && &header == SQLITE_HEADER)
}

fn migrate_plaintext_database(path: &Path, key: &[u8; 32]) -> Result<(), EchoMeshError> {
    // Flush plaintext WAL pages into the main database before the rename. Without
    // this step a stale `-wal` may both leak message contents and be orphaned by
    // the migration backup name.
    checkpoint_plaintext_database(path)?;
    remove_sqlite_sidecars(path)?;

    let backup = migration_backup_path(path);
    if backup.exists() {
        std::fs::remove_file(&backup)
            .map_err(|e| EchoMeshError::StorageError(format!("remove stale migration backup: {e}")))?;
    }
    std::fs::rename(path, &backup)
        .map_err(|e| EchoMeshError::StorageError(format!("stage plaintext migration: {e}")))?;

    let result = (|| {
        let source = Connection::open(&backup)
            .map_err(|e| EchoMeshError::StorageError(format!("open migration source: {e}")))?;
        let destination = sql_quote_path(path);
        source.execute_batch(&format!(
            "ATTACH DATABASE '{}' AS encrypted KEY \"x'{}'\";
             SELECT sqlcipher_export('encrypted');
             DETACH DATABASE encrypted;",
            destination, hex::encode(key)
        )).map_err(storage_err("export plaintext database into SQLCipher"))?;
        drop(source);

        let verify = Connection::open(path)
            .map_err(|e| EchoMeshError::StorageError(format!("open migrated database: {e}")))?;
        apply_sqlcipher_key(&verify, key)?;
        verify_sqlcipher(&verify)?;
        Ok::<(), EchoMeshError>(())
    })();

    match result {
        Ok(()) => {
            let _ = std::fs::remove_file(&backup);
            remove_sqlite_sidecars(&backup)?;
            Ok(())
        }
        Err(err) => {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::rename(&backup, path);
            let _ = remove_sqlite_sidecars(&backup);
            Err(err)
        }
    }
}

fn checkpoint_plaintext_database(path: &Path) -> Result<(), EchoMeshError> {
    let conn = Connection::open(path)
        .map_err(|e| EchoMeshError::StorageError(format!("open plaintext database for checkpoint: {e}")))?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
        .map_err(storage_err("checkpoint plaintext database"))?;
    drop(conn);
    Ok(())
}

fn remove_sqlite_sidecars(path: &Path) -> Result<(), EchoMeshError> {
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(path, suffix);
        match std::fs::remove_file(&sidecar) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(EchoMeshError::StorageError(format!(
                    "remove plaintext SQLite sidecar {}: {err}", sidecar.display()
                )))
            }
        }
    }
    Ok(())
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn migration_backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".plaintext-migration");
    PathBuf::from(name)
}

fn sql_quote_path(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}

fn storage_err(context: &'static str) -> impl FnOnce(rusqlite::Error) -> EchoMeshError {
    move |e| EchoMeshError::StorageError(format!("{context}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_schema_round_trip() {
        let storage = StorageManager::new_in_memory().unwrap();
        assert!(storage.get_contacts().unwrap().iter().any(|c| c.peer_id == ECHO_SERVICE_PEER_ID));
    }

    #[test]
    fn durable_database_header_is_not_plain_sqlite() {
        let path = std::env::temp_dir().join(format!("echomesh-sqlcipher-{}.db", uuid::Uuid::new_v4()));
        let key = [0x5Au8; 32];
        {
            let storage = StorageManager::new_encrypted(&path, &key).unwrap();
            storage.save_contact(&Contact { peer_id: vec![9u8; 32], name: "Alice".into(), added_at: 1 }).unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() >= 16);
        assert_ne!(&bytes[..16], SQLITE_HEADER);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, "-wal"));
        let _ = std::fs::remove_file(sidecar_path(&path, "-shm"));
    }

    #[test]
    fn plaintext_migration_preserves_data_and_removes_sidecars() {
        let path = std::env::temp_dir().join(format!("echomesh-migrate-{}.db", uuid::Uuid::new_v4()));
        let key = [0x33u8; 32];
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=DELETE;
                 CREATE TABLE legacy_data(value TEXT NOT NULL);
                 INSERT INTO legacy_data(value) VALUES ('plaintext-secret');"
            ).unwrap();
        }
        let wal = sidecar_path(&path, "-wal");
        let shm = sidecar_path(&path, "-shm");
        std::fs::write(&wal, b"stale-plaintext-wal").unwrap();
        std::fs::write(&shm, b"stale-plaintext-shm").unwrap();

        let storage = StorageManager::new_encrypted(&path, &key).unwrap();
        drop(storage);
        assert!(!wal.exists());
        assert!(!shm.exists());
        let bytes = std::fs::read(&path).unwrap();
        assert_ne!(&bytes[..16], SQLITE_HEADER);

        let verify = Connection::open(&path).unwrap();
        apply_sqlcipher_key(&verify, &key).unwrap();
        let value: String = verify.query_row("SELECT value FROM legacy_data", [], |row| row.get(0)).unwrap();
        assert_eq!(value, "plaintext-secret");
        drop(verify);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(sidecar_path(&path, "-wal"));
        let _ = std::fs::remove_file(sidecar_path(&path, "-shm"));
    }
}
