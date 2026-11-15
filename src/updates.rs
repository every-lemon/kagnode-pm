//! Fixed local application-manager transport. Host authorization stays in web.rs.
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::io::{Read, Write};
pub async fn request(action: &str, input: Value) -> Result<Value> {
    ensure!(
        matches!(action, "state" | "check" | "policy" | "apply"),
        "Unknown application update action"
    );
    let action = action.to_string();
    tokio::task::spawn_blocking(move|| {
        let socket=std::path::Path::new("/srv/kagnode/run/proxy-manager.sock");
        if !socket.exists() && action=="state" {return Ok(json!({"enabled":false,"message":"Enable the local application update manager with KagNode Daemon on this server."}));}
        let mut stream=std::os::unix::net::UnixStream::connect(socket).map_err(|_|anyhow::anyhow!("The local application update manager is unavailable"))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(45)))?;stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut value=input.as_object().cloned().ok_or_else(||anyhow::anyhow!("Update parameters must be an object"))?;
        value.insert("action".into(),json!(action));let bytes=serde_json::to_vec(&value)?;ensure!(bytes.len()<=4096,"Update request is too large");
        write!(stream,"POST / HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len())?;stream.write_all(&bytes)?;
        let mut response=Vec::new();stream.take(73729).read_to_end(&mut response)?;ensure!(response.len()<=73728,"Update response is too large");
        let split=response.windows(4).position(|w|w==b"\r\n\r\n").ok_or_else(||anyhow::anyhow!("Invalid update response"))?;ensure!(split<=8192,"Invalid update response headers");
        let header=std::str::from_utf8(&response[..split])?;let code=header.lines().next().and_then(|l|l.split_whitespace().nth(1)).and_then(|n|n.parse::<u16>().ok()).ok_or_else(||anyhow::anyhow!("Invalid update status"))?;
        let value:Value=serde_json::from_slice(&response[split+4..])?;
        ensure!((200..300).contains(&code),"{}",value["error"].as_str().unwrap_or("Update request failed"));Ok(value)
    }).await?
}
