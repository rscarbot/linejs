use crate::device::DeviceDetails;
use reqwest::{header, Client, Response};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RequestError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error: {0}")]
    Api(String),
}

pub struct RequestClient {
    pub client: Client,
    pub endpoint: String,
    pub device_details: DeviceDetails,
    pub auth_token: Option<String>,
}

impl RequestClient {
    pub fn new(device_details: DeviceDetails, endpoint: Option<String>) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.unwrap_or_else(|| "legy.line-apps.com".to_string()),
            device_details,
            auth_token: None,
        }
    }

    pub fn set_auth_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    pub async fn post_thrift(&self, path: &str, body: Vec<u8>, extra_headers: Option<HashMap<String, String>>) -> Result<Response, RequestError> {
        self.post_thrift_with_timeout(path, body, extra_headers, None).await
    }

    // Post a thrift request with a custom timeout duration for long-polling endpoints
    pub async fn post_thrift_with_timeout(&self, path: &str, body: Vec<u8>, extra_headers: Option<HashMap<String, String>>, timeout: Option<std::time::Duration>) -> Result<Response, RequestError> {
        println!("[DEBUG] Request {} bytes: {}", path, hex::encode(&body));
        let url = format!("https://{}{}", self.endpoint, path);
        let mut headers = header::HeaderMap::new();
        headers.insert(header::HOST, header::HeaderValue::from_str(&self.endpoint).unwrap());
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("application/x-thrift"));
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/x-thrift"));
        headers.insert(header::USER_AGENT, header::HeaderValue::from_str(&self.device_details.user_agent()).unwrap());
        headers.insert("x-line-application", header::HeaderValue::from_str(&self.device_details.x_line_application()).unwrap());
        headers.insert("x-lal", header::HeaderValue::from_static("ja_JP"));
        headers.insert("x-lpv", header::HeaderValue::from_static("1"));
        headers.insert("x-lhm", header::HeaderValue::from_static("POST"));

        if let Some(token) = &self.auth_token {
            headers.insert("x-line-access", header::HeaderValue::from_str(token).unwrap());
        }

        if let Some(extras) = extra_headers {
            for (k, v) in extras {
                headers.insert(header::HeaderName::from_bytes(k.as_bytes()).unwrap(), header::HeaderValue::from_str(&v).unwrap());
            }
        }

        // Build request with optional timeout for long-polling
        let mut req = self.client.post(url).headers(headers).body(body);
        if let Some(t) = timeout {
            req = req.timeout(t);
        }

        let res = req.send().await?;
        Ok(res)
    }
}
