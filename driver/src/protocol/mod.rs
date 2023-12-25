use crate::{logger::LogLine, types::PacketInfo};
use alloc::{format, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

struct ByteWriter(Vec<u8>);

impl ByteWriter {
    fn get(self) -> Vec<u8> {
        self.0
    }
}

impl ciborium_io::Write for ByteWriter {
    type Error = ();
    fn write_all(&mut self, data: &[u8]) -> Result<(), ()> {
        self.0.extend_from_slice(data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

struct ByteReader<'a>(&'a [u8]);

impl<'a> ciborium_io::Read for ByteReader<'a> {
    type Error = ();

    fn read_exact(&mut self, data: &mut [u8]) -> Result<(), Self::Error> {
        for (i, value) in data.iter_mut().enumerate() {
            if i >= self.0.len() {
                return Err(());
            }
            *value = self.0[i];
        }

        self.0 = &self.0[data.len()..];

        Ok(())
    }
}

// Driver structs
#[derive(Serialize, Deserialize, Debug)]
pub enum Info {
    Connection {
        id: u64,
        process_id: Option<u64>,
        process_path: Option<String>,
        direction: u8,
        ip_v6: bool,
        protocol: u8,
        local_ip: [u8; 4],
        remote_ip: [u8; 4],
        local_port: u16,
        remote_port: u16,
    },
    LogLines(Vec<LogLine>),
}

impl Info {
    pub fn serialize(self) -> Result<Vec<u8>, ()> {
        let mut buffer = ByteWriter(Vec::new());
        _ = ciborium::into_writer(&self, &mut buffer);
        Ok(buffer.get())
    }
}

impl PacketInfo {
    pub fn serialize(&self, id: u64) -> Result<Vec<u8>, ()> {
        // Build data.
        let connection = Info::Connection {
            id,
            process_id: self.process_id,
            process_path: self.process_path.clone(),
            direction: self.direction as u8,
            ip_v6: self.ip_v6,
            protocol: self.protocol,
            local_ip: self.local_ip,
            remote_ip: self.remote_ip,
            local_port: self.local_port,
            remote_port: self.remote_port,
        };

        connection.serialize()
    }
}

// User structs
#[derive(Serialize, Deserialize)]
pub enum Command {
    Shutdown(),
    Verdict {
        id: u64,
        verdict: u8,
    },
    Redirect {
        id: u64,
        remote_address: Vec<u8>,
        remote_port: u16,
    },
    Update {
        protocol: u8,
        local_address: Vec<u8>,
        local_port: u16,
        remote_address: Vec<u8>,
        remote_port: u16,
        verdict: u8,
        redirect_address: Vec<u8>,
        redirect_port: u16,
    },
    ClearCache(),
    GetLogs(),
}

pub fn parse_command(data: &[u8]) -> Result<Command, String> {
    let byte_reader = ByteReader(data);
    match ciborium::from_reader::<Command, ByteReader>(byte_reader) {
        Ok(command) => Ok(command),
        Err(err) => Err(format!("{}", err)),
    }
}
