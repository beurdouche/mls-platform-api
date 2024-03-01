use serde::{Deserialize, Serialize};
pub use serde_json::error::Error as SerdeError;

//
// Json (String)
//
pub struct Json<T>(pub T);

impl<T> Json<T>
where
    T: serde::Serialize,
{
    /// Serializes the contained value into a JSON string.
    pub fn serialize(&self) -> Result<String, SerdeError> {
        serde_json::to_string(&self.0)
    }
}

impl<T> Json<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    /// Deserializes a JSON string into the contained value.
    pub fn deserialize(s: &str) -> Result<T, SerdeError> {
        serde_json::from_str(s)
    }
}

//
// JsonBytes
//
pub struct JsonBytes<T>(pub T);

impl<T> JsonBytes<T>
where
    T: serde::Serialize,
{
    /// Serializes the contained value into a JSON byte vector.
    pub fn serialize(&self) -> Result<Vec<u8>, SerdeError> {
        serde_json::to_vec(&self.0)
    }
}

impl<T> JsonBytes<T>
where
    T: for<'de> Deserialize<'de>,
{
    /// Deserializes a JSON byte vector into the contained value.
    pub fn deserialize(bytes: &[u8]) -> Result<T, SerdeError> {
        serde_json::from_slice(bytes)
    }
}

pub fn to_json_bytes<T>(value: &T) -> Result<Vec<u8>, SerdeError>
where
    T: Serialize,
{
    JsonBytes(value).serialize()
}

pub fn from_json_bytes<'a, T>(bytes: &'a [u8]) -> Result<T, SerdeError>
where
    T: for<'de> serde::Deserialize<'de>,
{
    JsonBytes::deserialize(bytes)
}
