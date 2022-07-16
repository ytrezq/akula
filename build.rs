use anyhow::Result;
use std::process::Command;
use vergen::*;

fn main() -> Result<()> {
    let otterscan_dir = std::fs::canonicalize("src/otterscan")?;

    for cmds in [&["install"] as &[&str], &["run", "build"]] {
        assert!(Command::new("npm")
            .current_dir(&otterscan_dir)
            .args(cmds)
            .status()?
            .success());
    }

    let mut config = Config::default();
    *config.git_mut().commit_timestamp_kind_mut() = TimestampKind::DateOnly;
    *config.git_mut().sha_kind_mut() = ShaKind::Short;
    vergen(config)
}
