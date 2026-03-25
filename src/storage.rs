use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("storage backend error: {0}")]
    BackendError(String),
}

/// Trait for pluggable storage backends (S3, GDrive, local, etc.)
#[allow(async_fn_in_trait)]
pub trait StorageAdapter {
    /// Upload an encrypted blob, returns the storage key.
    async fn put(&self, key: &str, data: &[u8]) -> Result<String, StorageError>;

    /// Download an encrypted blob by key.
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError>;

    /// Delete an encrypted blob by key.
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// Generate a presigned PUT URL for direct upload.
    async fn presigned_put_url(
        &self,
        _key: &str,
        _expires_in_secs: u64,
    ) -> Result<String, StorageError> {
        Err(StorageError::BackendError(
            "presigned URLs not supported".into(),
        ))
    }
}
