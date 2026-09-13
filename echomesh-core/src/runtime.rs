use std::sync::{Arc, OnceLock};

use crate::EchoMeshError;

static RUNTIME: OnceLock<Arc<tokio::runtime::Runtime>> = OnceLock::new();

pub fn shared_runtime() -> Result<Arc<tokio::runtime::Runtime>, EchoMeshError> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime.clone());
    }

    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("echomesh-core")
            .enable_all()
            .build()
            .map_err(|e| EchoMeshError::RuntimeError(e.to_string()))?,
    );
    let _ = RUNTIME.set(runtime.clone());
    Ok(RUNTIME.get().cloned().unwrap_or(runtime))
}
