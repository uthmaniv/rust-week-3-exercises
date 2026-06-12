use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Bitcoin CompactSize encoding depends on the magnitude of the value.
        // For small values (<= 252), it's just a single byte.
        if self.value <= 0xfc {
            vec![self.value as u8]
        }
        // If it fits in 2 bytes, we prefix with 0xFD
        else if self.value <= 0xffff {
            let mut encoded = Vec::with_capacity(3);
            encoded.push(0xfd);
            encoded.extend_from_slice(&(self.value as u16).to_le_bytes());
            encoded
        }
        // If it fits in 4 bytes, we prefix with 0xFE
        else if self.value <= 0xffffffff {
            let mut encoded = Vec::with_capacity(5);
            encoded.push(0xfe);
            encoded.extend_from_slice(&(self.value as u32).to_le_bytes());
            encoded
        }
        // For larger values up to 8 bytes, we prefix with 0xFF
        else {
            let mut encoded = Vec::with_capacity(9);
            encoded.push(0xff);
            encoded.extend_from_slice(&self.value.to_le_bytes());
            encoded
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.is_empty() {
            return Err(BitcoinError::InsufficientBytes);
        }

        // The first byte tells us how to read the rest of the integer
        match bytes[0] {
            // Values 0-252 are read directly as a single byte
            0..=0xfc => Ok((
                CompactSize {
                    value: bytes[0] as u64,
                },
                1,
            )),

            // 0xFD means read the next 2 bytes as a little-endian u16
            0xfd => {
                if bytes.len() < 3 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u16::from_le_bytes(bytes[1..3].try_into().unwrap());
                Ok((
                    CompactSize {
                        value: value as u64,
                    },
                    3,
                ))
            }

            // 0xFE means read the next 4 bytes as a little-endian u32
            0xfe => {
                if bytes.len() < 5 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
                Ok((
                    CompactSize {
                        value: value as u64,
                    },
                    5,
                ))
            }

            // 0xFF means read the next 8 bytes as a little-endian u64
            0xff => {
                if bytes.len() < 9 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
                Ok((CompactSize { value }, 9))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Convert the 32-byte array to a hex string for easy JSON representation
        let hex_string = hex::encode(self.0);
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Parse the hex string back into a 32-byte array
        let hex_str = String::deserialize(deserializer)?;
        let raw_bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;

        if raw_bytes.len() != 32 {
            return Err(serde::de::Error::custom("Txid must be exactly 32 bytes"));
        }

        // Safely convert the dynamic slice into a fixed-size 32-byte array
        let txid_array: [u8; 32] = raw_bytes.try_into().unwrap();
        Ok(Txid(txid_array))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self {
            txid: Txid(txid),
            vout,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // An OutPoint is exactly 36 bytes: 32 bytes for txid + 4 bytes for vout
        let mut serialized = Vec::with_capacity(36);
        serialized.extend_from_slice(&self.txid.0);
        serialized.extend_from_slice(&self.vout.to_le_bytes());
        serialized
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }

        // Extract the 32-byte transaction ID
        let txid_bytes: [u8; 32] = bytes[0..32].try_into().unwrap();

        // Extract the 4-byte output index
        let vout = u32::from_le_bytes(bytes[32..36].try_into().unwrap());

        Ok((
            OutPoint {
                txid: Txid(txid_bytes),
                vout,
            },
            36, // OutPoint always consumes exactly 36 bytes
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // A script in a transaction is always prefixed by its length as a CompactSize
        let mut serialized = Vec::new();

        let length_prefix = CompactSize::new(self.bytes.len() as u64);
        serialized.extend_from_slice(&length_prefix.to_bytes());
        serialized.extend_from_slice(&self.bytes);

        serialized
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // First read the CompactSize to know how long the script is
        let (script_length, bytes_read) = CompactSize::from_bytes(bytes)?;
        let length_as_usize = script_length.value as usize;

        // Ensure we have enough bytes left to read the entire script
        if bytes.len() < bytes_read + length_as_usize {
            return Err(BitcoinError::InsufficientBytes);
        }

        // Extract exactly `script_length` bytes
        let script_content = bytes[bytes_read..bytes_read + length_as_usize].to_vec();

        Ok((
            Script {
                bytes: script_content,
            },
            bytes_read + length_as_usize, // Total bytes consumed: prefix length + script length
        ))
    }
}

impl Deref for Script {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        Self {
            previous_output,
            script_sig,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut serialized = Vec::new();

        // Serialize each part of the input in order
        serialized.extend_from_slice(&self.previous_output.to_bytes());
        serialized.extend_from_slice(&self.script_sig.to_bytes());
        serialized.extend_from_slice(&self.sequence.to_le_bytes());

        serialized
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Track how many bytes we've processed from the slice
        let mut total_bytes_read = 0;

        // 1. Read the outpoint (txid + vout)
        let (previous_output, outpoint_len) = OutPoint::from_bytes(bytes)?;
        total_bytes_read += outpoint_len;

        // 2. Read the script (length prefix + actual script)
        let (script_sig, script_len) = Script::from_bytes(&bytes[total_bytes_read..])?;
        total_bytes_read += script_len;

        // 3. Read the 4-byte sequence number
        if bytes.len() < total_bytes_read + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }

        let sequence_slice = &bytes[total_bytes_read..total_bytes_read + 4];
        let sequence = u32::from_le_bytes(sequence_slice.try_into().unwrap());
        total_bytes_read += 4;

        Ok((
            TransactionInput {
                previous_output,
                script_sig,
                sequence,
            },
            total_bytes_read,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        Self {
            version,
            inputs,
            lock_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut serialized = Vec::new();

        // 1. Serialize 4-byte version
        serialized.extend_from_slice(&self.version.to_le_bytes());

        // 2. Serialize the number of inputs as a CompactSize
        let input_count = CompactSize::new(self.inputs.len() as u64);
        serialized.extend_from_slice(&input_count.to_bytes());

        // 3. Serialize each input sequentially
        for input in &self.inputs {
            serialized.extend_from_slice(&input.to_bytes());
        }

        // 4. Serialize 4-byte lock time
        serialized.extend_from_slice(&self.lock_time.to_le_bytes());

        serialized
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let mut total_bytes_read = 0;

        // 1. Read the 4-byte version
        if bytes.len() < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        total_bytes_read += 4;

        // 2. Read the number of inputs
        let (input_count, count_len) = CompactSize::from_bytes(&bytes[total_bytes_read..])?;
        total_bytes_read += count_len;

        // 3. Parse each input
        let mut inputs = Vec::with_capacity(input_count.value as usize);
        for _ in 0..input_count.value {
            let (input, input_len) = TransactionInput::from_bytes(&bytes[total_bytes_read..])?;
            inputs.push(input);
            total_bytes_read += input_len;
        }

        // 4. Read the 4-byte lock time
        if bytes.len() < total_bytes_read + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }

        let lock_time_slice = &bytes[total_bytes_read..total_bytes_read + 4];
        let lock_time = u32::from_le_bytes(lock_time_slice.try_into().unwrap());
        total_bytes_read += 4;

        Ok((
            BitcoinTransaction {
                version,
                inputs,
                lock_time,
            },
            total_bytes_read,
        ))
    }
}

impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Transaction:")?;
        writeln!(f, "  Version: {}", self.version)?;
        writeln!(f, "  Inputs ({}):", self.inputs.len())?;

        for (index, input) in self.inputs.iter().enumerate() {
            writeln!(f, "    Input {}:", index)?;
            writeln!(
                f,
                "      Previous Txid: {}",
                hex::encode(input.previous_output.txid.0)
            )?;
            writeln!(
                f,
                "      Previous Output Vout: {}",
                input.previous_output.vout
            )?;
            writeln!(f, "      ScriptSig Length: {}", input.script_sig.len())?;
            writeln!(
                f,
                "      ScriptSig Bytes: {}",
                hex::encode(&input.script_sig.bytes)
            )?;
            writeln!(f, "      Sequence: {}", input.sequence)?;
        }

        write!(f, "  Lock Time: {}", self.lock_time)
    }
}
