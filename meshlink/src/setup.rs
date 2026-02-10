use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

const MESHLINK_DIR: &str = "/etc/meshlink";
const CONFIG_PATH: &str = "/etc/meshlink/config.toml";
const CREDENTIALS_PATH: &str = "/etc/meshlink/credentials.json";
const GROUP_NAME: &str = "meshlink";

/// Run the full setup: create group, directory, set permissions, add user.
pub fn run_setup() -> Result<()> {
    if !is_root() {
        eprintln!("Error: meshlink setup requires root privileges.");
        eprintln!();
        eprintln!("  Run: sudo meshlink setup");
        eprintln!();
        std::process::exit(1);
    }

    let mut actions: Vec<String> = Vec::new();

    // Create system group
    if !group_exists(GROUP_NAME)? {
        create_system_group(GROUP_NAME)?;
        actions.push(format!("Created system group '{GROUP_NAME}'"));
    } else {
        actions.push(format!("Group '{GROUP_NAME}' already exists (skipped)"));
    }

    // Create directory
    let dir = Path::new(MESHLINK_DIR);
    if !dir.exists() {
        std::fs::create_dir_all(dir).context("creating /etc/meshlink")?;
        actions.push(format!("Created directory {MESHLINK_DIR}"));
    } else {
        actions.push(format!("Directory {MESHLINK_DIR} already exists (skipped)"));
    }

    // Set directory ownership and permissions (root:meshlink, 2775 = setgid)
    chown(MESHLINK_DIR, "root", GROUP_NAME)?;
    chmod(MESHLINK_DIR, "2775")?;
    actions.push(format!(
        "Set {MESHLINK_DIR} ownership to root:{GROUP_NAME} mode 2775"
    ));

    // Create config.toml placeholder if missing
    let config_path = Path::new(CONFIG_PATH);
    if !config_path.exists() {
        std::fs::write(config_path, minimal_config_template()).context("creating config.toml")?;
        actions.push(format!("Created {CONFIG_PATH} (template)"));
    } else {
        actions.push(format!("{CONFIG_PATH} already exists (skipped creation)"));
    }

    // Set config file ownership and permissions (root:meshlink, 0664)
    chown(CONFIG_PATH, "root", GROUP_NAME)?;
    chmod(CONFIG_PATH, "0664")?;
    actions.push(format!(
        "Set {CONFIG_PATH} ownership to root:{GROUP_NAME} mode 0664"
    ));

    // Fix credentials.json permissions if it exists
    let creds_path = Path::new(CREDENTIALS_PATH);
    if creds_path.exists() {
        chown(CREDENTIALS_PATH, "root", GROUP_NAME)?;
        chmod(CREDENTIALS_PATH, "0660")?;
        actions.push(format!(
            "Set {CREDENTIALS_PATH} ownership to root:{GROUP_NAME} mode 0660"
        ));
    }

    // Add the calling user (behind sudo) to the meshlink group
    if let Some(real_user) = get_sudo_user() {
        add_user_to_group(&real_user, GROUP_NAME)?;
        actions.push(format!("Added user '{real_user}' to group '{GROUP_NAME}'"));
    } else {
        actions.push("No $SUDO_USER detected; skipping user group membership".to_string());
    }

    // Print summary
    println!("meshlink setup complete:");
    println!();
    for action in &actions {
        println!("  [done] {action}");
    }
    println!();
    println!("You may need to log out and back in for group membership to take effect.");
    println!("Then run: meshlink register --server <URL> --invite <CODE>");

    Ok(())
}

/// Check if the current process is running as root (uid 0).
fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Check if a system group exists by name.
fn group_exists(name: &str) -> Result<bool> {
    let status = Command::new("getent")
        .args(["group", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("running getent")?;
    Ok(status.success())
}

/// Create a system group.
fn create_system_group(name: &str) -> Result<()> {
    let status = Command::new("groupadd")
        .args(["--system", name])
        .status()
        .context("running groupadd")?;
    if !status.success() {
        bail!("groupadd --system {name} failed with exit code {status}");
    }
    Ok(())
}

/// Change ownership of a path.
fn chown(path: &str, user: &str, group: &str) -> Result<()> {
    let status = Command::new("chown")
        .arg(format!("{user}:{group}"))
        .arg(path)
        .status()
        .with_context(|| format!("running chown on {path}"))?;
    if !status.success() {
        bail!("chown {user}:{group} {path} failed");
    }
    Ok(())
}

/// Change permissions of a path.
fn chmod(path: &str, mode: &str) -> Result<()> {
    let status = Command::new("chmod")
        .arg(mode)
        .arg(path)
        .status()
        .with_context(|| format!("running chmod on {path}"))?;
    if !status.success() {
        bail!("chmod {mode} {path} failed");
    }
    Ok(())
}

/// Add a user to a group.
fn add_user_to_group(user: &str, group: &str) -> Result<()> {
    let status = Command::new("usermod")
        .args(["-aG", group, user])
        .status()
        .with_context(|| format!("running usermod -aG {group} {user}"))?;
    if !status.success() {
        bail!("usermod -aG {group} {user} failed");
    }
    Ok(())
}

/// Get the real user behind sudo (from $SUDO_USER).
fn get_sudo_user() -> Option<String> {
    std::env::var("SUDO_USER").ok().filter(|s| !s.is_empty())
}

/// Minimal config template written when no config exists yet.
fn minimal_config_template() -> &'static str {
    "# MeshLink configuration\n\
     # This file will be populated during registration.\n\
     # Run: meshlink register --server <URL> --invite <CODE>\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_not_root_in_tests() {
        assert!(!is_root());
    }

    #[test]
    fn test_group_exists_root() {
        assert!(group_exists("root").unwrap());
    }

    #[test]
    fn test_group_exists_nonexistent() {
        assert!(!group_exists("meshlink_nonexistent_test_group_xyz").unwrap());
    }

    #[test]
    fn test_get_sudo_user_absent() {
        std::env::remove_var("SUDO_USER");
        assert!(get_sudo_user().is_none());
    }

    #[test]
    fn test_get_sudo_user_present() {
        std::env::set_var("SUDO_USER", "testuser");
        assert_eq!(get_sudo_user(), Some("testuser".to_string()));
        std::env::remove_var("SUDO_USER");
    }

    #[test]
    fn test_minimal_config_template_not_empty() {
        let tmpl = minimal_config_template();
        assert!(tmpl.contains("MeshLink"));
        assert!(!tmpl.is_empty());
    }
}
