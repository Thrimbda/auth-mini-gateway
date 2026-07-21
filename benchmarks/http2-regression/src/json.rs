use crate::{Error, Result};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use std::fmt::Formatter;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempFileGuard {
    path: std::path::PathBuf,
    armed: bool,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON key `{key}`"
                )));
            }
            let value = object.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct StrictValueSeed;

impl<'de> serde::de::DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

pub fn from_slice_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = deserializer.deserialize_any(StrictValueVisitor)?;
    deserializer.end()?;
    serde_json::from_value(value).map_err(Into::into)
}

pub fn read_strict<T: DeserializeOwned>(path: &Path, maximum_bytes: u64) -> Result<T> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Error::new(format!("cannot stat {}: {error}", path.display())))?;
    if !metadata.file_type().is_file() {
        return Err(Error::new(format!(
            "JSON path is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(Error::new(format!(
            "JSON file exceeds {maximum_bytes} bytes: {}",
            path.display()
        )));
    }
    let bytes = fs::read(path)
        .map_err(|error| Error::new(format!("cannot read {}: {error}", path.display())))?;
    from_slice_strict(&bytes)
}

fn sorted_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sorted_value).collect()),
        Value::Object(values) => {
            let mut pairs: Vec<_> = values.into_iter().collect();
            pairs.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            let mut sorted = Map::new();
            for (key, value) in pairs {
                sorted.insert(key, sorted_value(value));
            }
            Value::Object(sorted)
        }
        primitive => primitive,
    }
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = sorted_value(serde_json::to_value(value)?);
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn require_canonical<T>(bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = from_slice_strict(bytes)?;
    if canonical_bytes(&value)? != bytes {
        return Err(Error::new("JSON is not in canonical sorted form"));
    }
    Ok(value)
}

pub fn write_new_canonical<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>> {
    let bytes = canonical_bytes(value)?;
    write_new_bytes(path, &bytes)?;
    Ok(bytes)
}

pub fn write_new_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("output path has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir() {
        return Err(Error::new("output parent is not a directory"));
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Error::new("output file name is not UTF-8"))?;
    let temp = parent.join(format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| Error::new(format!("cannot create {}: {error}", temp.display())))?;
    let mut guard = TempFileGuard {
        path: temp.clone(),
        armed: true,
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::hard_link(&temp, path) {
        return Err(Error::new(format!(
            "cannot atomically install {} without replacement: {error}",
            path.display()
        )));
    }
    fs::remove_file(&temp)?;
    guard.armed = false;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        a: u64,
        z: u64,
    }

    #[test]
    fn rejects_duplicate_and_unknown_keys() {
        assert!(from_slice_strict::<Fixture>(br#"{"a":1,"a":2,"z":3}"#).is_err());
        assert!(from_slice_strict::<Fixture>(br#"{"a":1,"z":2,"x":3}"#).is_err());
    }

    #[test]
    fn canonical_json_sorts_keys_and_ends_with_lf() {
        let bytes = canonical_bytes(&Fixture { a: 1, z: 2 }).expect("canonical JSON");
        assert_eq!(bytes, b"{\"a\":1,\"z\":2}\n");
        assert_eq!(
            require_canonical::<Fixture>(&bytes).expect("canonical input"),
            Fixture { a: 1, z: 2 }
        );
        assert!(require_canonical::<Fixture>(b"{\"z\":2,\"a\":1}\n").is_err());
    }

    #[test]
    fn atomic_no_replace_write_preserves_destination_and_cleans_failed_temp() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("atomic-write-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("atomic test directory");
        let destination = directory.join("result.json");
        fs::write(&destination, b"original").expect("existing destination");
        assert!(write_new_bytes(&destination, b"replacement").is_err());
        assert_eq!(fs::read(&destination).expect("destination"), b"original");
        assert!(fs::read_dir(&directory)
            .expect("directory")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .contains(".tmp.")));

        let fresh = directory.join("fresh.json");
        write_new_bytes(&fresh, b"complete").expect("atomic fresh write");
        assert_eq!(fs::read(fresh).expect("fresh bytes"), b"complete");
        fs::remove_dir_all(directory).expect("clean atomic fixture");
    }
}
