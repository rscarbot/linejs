use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceType {
    DESKTOPWIN,
    DESKTOPMAC,
    ANDROID,
    IOS,
    IOSIPAD,
    WATCHOS,
    WEAROS,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::DESKTOPWIN => "DESKTOPWIN",
            DeviceType::DESKTOPMAC => "DESKTOPMAC",
            DeviceType::ANDROID => "ANDROID",
            DeviceType::IOS => "IOS",
            DeviceType::IOSIPAD => "IOSIPAD",
            DeviceType::WATCHOS => "WATCHOS",
            DeviceType::WEAROS => "WEAROS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDetails {
    pub device_type: DeviceType,
    pub app_version: String,
    pub system_name: String,
    pub system_version: String,
}

impl DeviceDetails {
    pub fn new(device_type: DeviceType, version: Option<String>) -> Self {
        let app_version = version.unwrap_or_else(|| match device_type {
            DeviceType::DESKTOPWIN => "9.2.0.3403".to_string(),
            DeviceType::DESKTOPMAC => "9.2.0.3402".to_string(),
            DeviceType::ANDROID => "13.4.1".to_string(),
            DeviceType::IOS | DeviceType::IOSIPAD | DeviceType::WATCHOS => "13.3.0".to_string(),
            DeviceType::WEAROS => "13.4.1".to_string(),
        });

        let system_name = match device_type {
            DeviceType::DESKTOPWIN => "WINDOWS",
            DeviceType::DESKTOPMAC => "MAC",
            DeviceType::ANDROID => "Android OS",
            DeviceType::IOS | DeviceType::IOSIPAD => "iOS",
            DeviceType::WATCHOS => "Watch OS",
            DeviceType::WEAROS => "Wear OS",
        }.to_string();

        let system_version = match device_type {
            DeviceType::DESKTOPWIN => "10.0.0-NT-x64",
            _ => "12.1.4",
        }.to_string();

        Self {
            device_type,
            app_version,
            system_name,
            system_version,
        }
    }

    pub fn x_line_application(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.device_type.as_str(),
            self.app_version,
            self.system_name,
            self.system_version
        )
    }

    pub fn user_agent(&self) -> String {
        format!("Line/{}", self.app_version)
    }
}
