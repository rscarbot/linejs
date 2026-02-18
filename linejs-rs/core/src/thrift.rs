use std::io::{Read, Write};
use thiserror::Error;
use base64::{Engine as _, engine::general_purpose};

#[derive(Error, Debug)]
pub enum ThriftError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, ThriftError>;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TType {
    Stop = 0, Void = 1, Bool = 2, Byte = 3, Double = 4, I16 = 6, I32 = 8, I64 = 10, String = 11, Struct = 12, Map = 13, Set = 14, List = 15,
}

impl TType {
    pub fn from_compact(t: u8) -> Self {
        match t {
            0x01 | 0x02 => TType::Bool,
            0x03 => TType::Byte,
            0x04 => TType::I16,
            0x05 => TType::I32,
            0x06 => TType::I64,
            0x07 => TType::Double,
            0x08 => TType::String,
            0x09 => TType::List,
            0x0A => TType::Set,
            0x0B => TType::Map,
            0x0C => TType::Struct,
            _ => TType::Stop,
        }
    }

    pub fn from_binary(t: u8) -> Self {
        match t {
            0 => TType::Stop, 1 => TType::Void, 2 => TType::Bool, 3 => TType::Byte,
            4 => TType::Double, 6 => TType::I16, 8 => TType::I32, 10 => TType::I64,
            11 => TType::String, 12 => TType::Struct, 13 => TType::Map,
            14 => TType::Set, 15 => TType::List,
            _ => TType::Stop,
        }
    }

    pub fn to_binary(&self) -> u8 { *self as u8 }

    pub fn to_compact(&self) -> u8 {
        match self {
            TType::Stop => 0x00,
            TType::Bool => 0x01, // Default to True, write_bool handles actual value
            TType::Byte => 0x03,
            TType::I16 => 0x04,
            TType::I32 => 0x05,
            TType::I64 => 0x06,
            TType::Double => 0x07,
            TType::String => 0x08,
            TType::List => 0x09,
            TType::Set => 0x0A,
            TType::Map => 0x0B,
            TType::Struct => 0x0C,
            _ => 0x00,
        }
    }
}

pub struct CompactProtocol<R: Read, W: Write> {
    pub reader: Option<R>,
    pub writer: Option<W>,
    last_field_id: i16,
    field_id_stack: Vec<i16>,
    boolean_field: Option<(i16, bool)>,
}

impl<R: Read, W: Write> CompactProtocol<R, W> {
    pub fn new(reader: Option<R>, writer: Option<W>) -> Self {
        Self { reader, writer, last_field_id: 0, field_id_stack: Vec::new(), boolean_field: None }
    }

    pub fn read_byte_raw(&mut self) -> Result<u8> { self.read_byte() }
    pub fn read_varint_raw(&mut self) -> Result<u64> { self.read_varint() }

    fn read_byte(&mut self) -> Result<u8> {
        let mut b = [0u8; 1];
        self.reader.as_mut().unwrap().read_exact(&mut b)?;
        Ok(b[0])
    }

    fn read_varint(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let b = self.read_byte()?;
            result |= ((b & 0x7f) as u64) << shift;
            if (b & 0x80) == 0 { break; }
            shift += 7;
        }
        Ok(result)
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        let n = self.read_varint()? as u32;
        Ok((n >> 1) as i32 ^ -((n & 1) as i32))
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        let n = self.read_varint()?;
        Ok((n >> 1) as i64 ^ -((n & 1) as i64))
    }

    pub fn read_string(&mut self) -> Result<String> {
        let len = self.read_varint()?;
        if len == 0 { return Ok(String::new()); }
        let mut buf = vec![0u8; len as usize];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        match String::from_utf8(buf.clone()) {
            Ok(s) => Ok(s),
            Err(_) => Ok(general_purpose::STANDARD.encode(&buf)),
        }
    }

    pub fn read_binary(&mut self) -> Result<Vec<u8>> {
        let len = self.read_varint()?;
        let mut buf = vec![0u8; len as usize];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn read_field_begin(&mut self) -> Result<(TType, i16)> {
        let b = self.read_byte()?;
        if b == 0 { return Ok((TType::Stop, 0)); }
        let modifier = (b & 0xf0) >> 4;
        let field_id = if modifier == 0 { self.read_i32()? as i16 } else { self.last_field_id + modifier as i16 };
        self.last_field_id = field_id;
        let type_bits = b & 0x0f;
        match type_bits {
            0x01 | 0x02 => { self.boolean_field = Some((field_id, type_bits == 0x01)); Ok((TType::Bool, field_id)) },
            t => Ok((TType::from_compact(t), field_id)),
        }
    }

    pub fn read_struct_begin(&mut self) -> Result<()> { self.field_id_stack.push(self.last_field_id); self.last_field_id = 0; Ok(()) }
    pub fn read_struct_end(&mut self) -> Result<()> { self.last_field_id = self.field_id_stack.pop().unwrap_or(0); Ok(()) }

    pub fn skip(&mut self, ttype: TType) -> Result<()> {
        match ttype {
            TType::Bool => { if self.boolean_field.is_none() { self.read_byte()?; } else { self.boolean_field = None; } },
            TType::Byte => { self.read_byte()?; },
            TType::I16 | TType::I32 => { self.read_i32()?; },
            TType::I64 => { self.read_i64()?; },
            TType::Double => { let mut buf = [0u8; 8]; self.reader.as_mut().unwrap().read_exact(&mut buf)?; },
            TType::String => { self.read_binary()?; },
            TType::Struct => {
                self.read_struct_begin()?;
                loop { let (ftype, _) = self.read_field_begin()?; if ftype == TType::Stop { break; } self.skip(ftype)?; }
                self.read_struct_end()?;
            },
            TType::Map => {
                // Compact protocol: varint size first, then types byte only if non-empty
                let size = self.read_varint()? as i32;
                if size > 0 {
                    let b = self.read_byte()?;
                    let ktype = TType::from_compact((b >> 4) & 0x0f);
                    let vtype = TType::from_compact(b & 0x0f);
                    for _ in 0..size { self.skip(ktype)?; self.skip(vtype)?; }
                }
            },
            TType::Set | TType::List => {
                let b = self.read_byte()?;
                let mut size = (b >> 4) as i32;
                if size == 15 { size = self.read_varint()? as i32; }
                let etype = TType::from_compact(b & 0x0f);
                for _ in 0..size { self.skip(etype)?; }
            },
            _ => {},
        }
        Ok(())
    }

    pub fn read_struct_to_value(&mut self) -> Result<serde_json::Value> {
        let mut map = serde_json::Map::new();
        self.read_struct_begin()?;
        loop {
            let (ttype, fid) = self.read_field_begin()?;
            if ttype == TType::Stop { break; }
            map.insert(fid.to_string(), self.read_value(ttype)?);
        }
        self.read_struct_end()?;
        Ok(serde_json::Value::Object(map))
    }

    pub fn read_value(&mut self, ttype: TType) -> Result<serde_json::Value> {
        match ttype {
            TType::Bool => {
                if let Some((_, val)) = self.boolean_field.take() { Ok(serde_json::Value::Bool(val)) }
                else { Ok(serde_json::Value::Bool(self.read_byte()? == 0x01)) }
            },
            TType::Byte => Ok(serde_json::Value::Number(self.read_byte()?.into())),
            TType::I16 | TType::I32 => Ok(serde_json::Value::Number(self.read_i32()?.into())),
            TType::I64 => Ok(serde_json::Value::Number(self.read_i64()?.into())),
            TType::Double => {
                let mut buf = [0u8; 8]; self.reader.as_mut().unwrap().read_exact(&mut buf)?;
                Ok(serde_json::json!(f64::from_le_bytes(buf)))
            },
            TType::String => {
                let bin = self.read_binary()?;
                if let Ok(s) = String::from_utf8(bin.clone()) { Ok(serde_json::Value::String(s)) }
                else { Ok(serde_json::Value::String(general_purpose::STANDARD.encode(&bin))) }
            },
            TType::Struct => self.read_struct_to_value(),
            TType::Map => {
                // Compact protocol: varint size first, then types byte only if non-empty
                let size = self.read_varint()? as i32;
                let mut map = serde_json::Map::new();
                if size > 0 {
                    let b = self.read_byte()?;
                    let ktype = TType::from_compact((b >> 4) & 0x0f);
                    let vtype = TType::from_compact(b & 0x0f);
                    for _ in 0..size {
                        let key_val = self.read_value(ktype)?;
                        let key_str = match key_val.as_str() {
                            Some(s) => s.to_string(),
                            None => key_val.to_string(),
                        };
                        map.insert(key_str, self.read_value(vtype)?);
                    }
                }
                Ok(serde_json::Value::Object(map))
            },
            TType::List | TType::Set => {
                let b = self.read_byte()?;
                let mut size = (b >> 4) as i32;
                if size == 15 { size = self.read_varint()? as i32; }
                let etype = TType::from_compact(b & 0x0f);
                let mut list = Vec::new();
                for _ in 0..size { list.push(self.read_value(etype)?); }
                Ok(serde_json::Value::Array(list))
            },
            _ => Ok(serde_json::Value::Null),
        }
    }

    pub fn read_message_begin(&mut self) -> Result<(String, u8, i32)> {
        if self.read_byte()? != 0x82 { return Err(ThriftError::Protocol("Invalid protocol ID".to_string())); }
        let vt = self.read_byte()?;
        let message_type = (vt >> 5) & 0x07;
        let seq_id = self.read_i32()?;
        let name = self.read_string()?;
        Ok((name, message_type, seq_id))
    }

    pub fn write_message_begin(&mut self, name: &str, message_type: u8, seq_id: i32) -> Result<()> {
        self.write_byte(0x82)?;
        self.write_byte((message_type << 5) | 0x01)?;
        self.write_i32(seq_id)?;
        self.write_string(name)?;
        Ok(())
    }

    fn write_byte(&mut self, b: u8) -> Result<()> {
        self.writer.as_mut().unwrap().write_all(&[b])?; Ok(())
    }

    fn write_varint(&mut self, mut n: u64) -> Result<()> {
        while (n & !0x7f) != 0 { self.write_byte(((n & 0x7f) | 0x80) as u8)?; n >>= 7; }
        self.write_byte(n as u8)?; Ok(())
    }

    pub fn write_i32(&mut self, n: i32) -> Result<()> { self.write_varint(((n << 1) ^ (n >> 31)) as u64) }
    pub fn write_i64(&mut self, n: i64) -> Result<()> { self.write_varint(((n << 1) ^ (n >> 63)) as u64) }

    pub fn write_string(&mut self, s: &str) -> Result<()> {
        self.write_varint(s.len() as u64)?;
        self.writer.as_mut().unwrap().write_all(s.as_bytes())?; Ok(())
    }

    pub fn write_field_begin(&mut self, ttype: TType, id: i16) -> Result<()> {
        if ttype == TType::Bool { self.boolean_field = Some((id, true)); return Ok(()); }
        let type_bits = ttype.to_compact();
        if id > self.last_field_id && id - self.last_field_id <= 15 {
            self.write_byte(((id - self.last_field_id) as u8) << 4 | type_bits)?;
        } else {
            self.write_byte(type_bits)?;
            self.write_i32(id as i32)?;
        }
        self.last_field_id = id;
        Ok(())
    }

    pub fn write_bool(&mut self, value: bool) -> Result<()> {
        if let Some((id, _)) = self.boolean_field.take() {
            let type_bits = if value { 0x01 } else { 0x02 };
            if id > self.last_field_id && id - self.last_field_id <= 15 {
                self.write_byte(((id - self.last_field_id) as u8) << 4 | type_bits)?;
            } else {
                self.write_byte(type_bits)?;
                self.write_i32(id as i32)?;
            }
            self.last_field_id = id;
        }
        Ok(())
    }

    /// Write compact protocol list header: (size << 4 | elem_type) if size < 15,
    /// else (0xF0 | elem_type) followed by varint size.
    pub fn write_list_begin(&mut self, elem_type: TType, size: usize) -> Result<()> {
        let type_bits = elem_type.to_compact();
        if size < 15 {
            self.write_byte(((size as u8) << 4) | type_bits)?;
        } else {
            self.write_byte(0xF0 | type_bits)?;
            self.write_varint(size as u64)?;
        }
        Ok(())
    }

    pub fn write_field_stop(&mut self) -> Result<()> { self.write_byte(0) }
    pub fn write_struct_begin(&mut self) -> Result<()> { self.field_id_stack.push(self.last_field_id); self.last_field_id = 0; Ok(()) }
    pub fn write_struct_end(&mut self) -> Result<()> { self.last_field_id = self.field_id_stack.pop().unwrap_or(0); Ok(()) }
}

// ── TBinaryProtocol ──────────────────────────────────────────────────

pub struct BinaryProtocol<R: Read, W: Write> {
    pub reader: Option<R>,
    pub writer: Option<W>,
}

impl<R: Read, W: Write> BinaryProtocol<R, W> {
    pub fn new(reader: Option<R>, writer: Option<W>) -> Self {
        Self { reader, writer }
    }

    // ── Read helpers ────────────────────────────────────────────────

    fn read_byte(&mut self) -> Result<u8> {
        let mut b = [0u8; 1];
        self.reader.as_mut().unwrap().read_exact(&mut b)?;
        Ok(b[0])
    }

    fn read_i16_raw(&mut self) -> Result<i16> {
        let mut buf = [0u8; 2];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        Ok(i16::from_be_bytes(buf))
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        Ok(i32::from_be_bytes(buf))
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        let mut buf = [0u8; 8];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        Ok(i64::from_be_bytes(buf))
    }

    pub fn read_string(&mut self) -> Result<String> {
        let len = self.read_i32()? as usize;
        if len == 0 { return Ok(String::new()); }
        let mut buf = vec![0u8; len];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        match String::from_utf8(buf.clone()) {
            Ok(s) => Ok(s),
            Err(_) => Ok(general_purpose::STANDARD.encode(&buf)),
        }
    }

    pub fn read_binary(&mut self) -> Result<Vec<u8>> {
        let len = self.read_i32()? as usize;
        let mut buf = vec![0u8; len];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn read_message_begin(&mut self) -> Result<(String, u8, i32)> {
        let version = self.read_i32()?;
        if (version & 0xffff0000u32 as i32) != 0x80010000u32 as i32 {
            return Err(ThriftError::Protocol("Invalid binary protocol version".to_string()));
        }
        let msg_type = (version & 0x000000ff) as u8;
        let name = self.read_string()?;
        let seq_id = self.read_i32()?;
        Ok((name, msg_type, seq_id))
    }

    pub fn read_field_begin(&mut self) -> Result<(TType, i16)> {
        let type_byte = self.read_byte()?;
        if type_byte == 0 { return Ok((TType::Stop, 0)); }
        let field_id = self.read_i16_raw()?;
        let ttype = TType::from_binary(type_byte);
        Ok((ttype, field_id))
    }

    pub fn skip(&mut self, ttype: TType) -> Result<()> {
        match ttype {
            TType::Bool | TType::Byte => { self.read_byte()?; },
            TType::I16 => { self.read_i16_raw()?; },
            TType::I32 => { self.read_i32()?; },
            TType::I64 => { self.read_i64()?; },
            TType::Double => { let mut buf = [0u8; 8]; self.reader.as_mut().unwrap().read_exact(&mut buf)?; },
            TType::String => { self.read_binary()?; },
            TType::Struct => {
                loop { let (ft, _) = self.read_field_begin()?; if ft == TType::Stop { break; } self.skip(ft)?; }
            },
            TType::Map => {
                let kt = TType::from_binary(self.read_byte()?);
                let vt = TType::from_binary(self.read_byte()?);
                let size = self.read_i32()?;
                for _ in 0..size { self.skip(kt)?; self.skip(vt)?; }
            },
            TType::Set | TType::List => {
                let et = TType::from_binary(self.read_byte()?);
                let size = self.read_i32()?;
                for _ in 0..size { self.skip(et)?; }
            },
            _ => {},
        }
        Ok(())
    }

    pub fn read_value(&mut self, ttype: TType) -> Result<serde_json::Value> {
        match ttype {
            TType::Bool => Ok(serde_json::Value::Bool(self.read_byte()? != 0)),
            TType::Byte => Ok(serde_json::Value::Number(self.read_byte()?.into())),
            TType::I16 => Ok(serde_json::Value::Number(self.read_i16_raw()?.into())),
            TType::I32 => Ok(serde_json::Value::Number(self.read_i32()?.into())),
            TType::I64 => Ok(serde_json::Value::Number(self.read_i64()?.into())),
            TType::Double => {
                let mut buf = [0u8; 8]; self.reader.as_mut().unwrap().read_exact(&mut buf)?;
                Ok(serde_json::json!(f64::from_be_bytes(buf)))
            },
            TType::String => {
                let bin = self.read_binary()?;
                if let Ok(s) = String::from_utf8(bin.clone()) { Ok(serde_json::Value::String(s)) }
                else { Ok(serde_json::Value::String(general_purpose::STANDARD.encode(&bin))) }
            },
            TType::Struct => self.read_struct_to_value(),
            TType::Map => {
                let kt = TType::from_binary(self.read_byte()?);
                let vt = TType::from_binary(self.read_byte()?);
                let size = self.read_i32()?;
                let mut map = serde_json::Map::new();
                for _ in 0..size {
                    let key_val = self.read_value(kt)?;
                    let key_str = match key_val.as_str() {
                        Some(s) => s.to_string(),
                        None => key_val.to_string(),
                    };
                    map.insert(key_str, self.read_value(vt)?);
                }
                Ok(serde_json::Value::Object(map))
            },
            TType::List | TType::Set => {
                let et = TType::from_binary(self.read_byte()?);
                let size = self.read_i32()?;
                let mut list = Vec::new();
                for _ in 0..size { list.push(self.read_value(et)?); }
                Ok(serde_json::Value::Array(list))
            },
            _ => Ok(serde_json::Value::Null),
        }
    }

    pub fn read_struct_to_value(&mut self) -> Result<serde_json::Value> {
        let mut map = serde_json::Map::new();
        loop {
            let (ttype, fid) = self.read_field_begin()?;
            if ttype == TType::Stop { break; }
            map.insert(fid.to_string(), self.read_value(ttype)?);
        }
        Ok(serde_json::Value::Object(map))
    }

    // ── Write helpers ───────────────────────────────────────────────

    fn write_byte(&mut self, b: u8) -> Result<()> {
        self.writer.as_mut().unwrap().write_all(&[b])?; Ok(())
    }

    pub fn write_i32(&mut self, n: i32) -> Result<()> {
        self.writer.as_mut().unwrap().write_all(&n.to_be_bytes())?; Ok(())
    }

    pub fn write_string(&mut self, s: &str) -> Result<()> {
        self.write_i32(s.len() as i32)?;
        self.writer.as_mut().unwrap().write_all(s.as_bytes())?; Ok(())
    }

    pub fn write_binary(&mut self, data: &[u8]) -> Result<()> {
        self.write_i32(data.len() as i32)?;
        self.writer.as_mut().unwrap().write_all(data)?; Ok(())
    }

    pub fn write_bool(&mut self, value: bool) -> Result<()> {
        self.write_byte(if value { 1 } else { 0 })
    }

    pub fn write_field_begin(&mut self, ttype: TType, id: i16) -> Result<()> {
        self.write_byte(ttype.to_binary())?;
        self.writer.as_mut().unwrap().write_all(&id.to_be_bytes())?;
        Ok(())
    }

    pub fn write_field_stop(&mut self) -> Result<()> { self.write_byte(0) }

    pub fn write_message_begin(&mut self, name: &str, message_type: u8, seq_id: i32) -> Result<()> {
        let version = 0x80010000u32 as i32 | (message_type as i32);
        self.write_i32(version)?;
        self.write_string(name)?;
        self.write_i32(seq_id)?;
        Ok(())
    }
}
