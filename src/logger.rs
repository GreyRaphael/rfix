use chrono::{DateTime, Utc};
use fast_log;
use fast_log::appender::{FastLogRecord, RecordFormat};
use fast_log::config::Config;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Deserialize)]
struct ConfigFile {
    root: RootConfig,
    appenders: HashMap<String, AppenderConfig>,
}

#[derive(Debug, Deserialize)]
struct RootConfig {
    level: String,
    appenders: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
enum AppenderConfig {
    #[serde(rename = "console")]
    Console,
    #[serde(rename = "file")]
    File { path: String },
}

pub struct NanoFormatter;

impl RecordFormat for NanoFormatter {
    fn do_format(&self, record: &mut FastLogRecord) {
        record.formated = format!(
            "{} [{}] {}\n",
            // DateTime::<Local>::from(record.now).format("%FT%T%.9f"),
            DateTime::<Utc>::from(record.now).format("%FT%T%.9f"),
            record.level,
            record.args
        );
    }
}

pub fn init_logger() -> anyhow::Result<()> {
    let cfg_str = fs::read_to_string("config/log.toml")?;
    let parsed: ConfigFile = toml::from_str(&cfg_str)?;
    // println!("config = {:?}", parsed);

    let mut fast_cfg = Config::new()
        .level(parsed.root.level.parse::<log::LevelFilter>()?)
        .format(NanoFormatter)
        .chan_len(Some(10240));

    for appender_name in &parsed.root.appenders {
        match parsed.appenders.get(appender_name) {
            Some(AppenderConfig::Console) => {
                fast_cfg = fast_cfg.console();
            }
            Some(AppenderConfig::File { path }) => {
                fast_cfg = fast_cfg.file(path);
            }
            None => {
                panic!("Appender `{}` not defined in [appenders]", appender_name);
            }
        }
    }

    fast_log::init(fast_cfg).expect("init logger"); // for debug
    Ok(())
}
