use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

const GROUP_NAME: &str = "meshlink";

/// Run the full setup: create group, directory, set permissions, add user.
pub fn run_setup(config_dir: &Path) -> Result<()> {
    if !is_root() {
        eprintln!("Error: meshlink setup requires root privileges.");
        eprintln!();
        eprintln!("  Run: sudo meshlink setup");
        eprintln!();
        std::process::exit(1);
    }

    let dir_str = config_dir.display().to_string();
    let config_path = config_dir.join("config.toml");
    let config_str = config_path.display().to_string();
    let creds_path = config_dir.join("credentials.json");
    let creds_str = creds_path.display().to_string();

    let mut actions: Vec<String> = Vec::new();

    // Create system group
    if !group_exists(GROUP_NAME)? {
        create_system_group(GROUP_NAME)?;
        actions.push(format!("Created system group '{GROUP_NAME}'"));
    } else {
        actions.push(format!("Group '{GROUP_NAME}' already exists (skipped)"));
    }

    // Create directory
    if !config_dir.exists() {
        std::fs::create_dir_all(config_dir)
            .with_context(|| format!("creating {dir_str}"))?;
        actions.push(format!("Created directory {dir_str}"));
    } else {
        actions.push(format!("Directory {dir_str} already exists (skipped)"));
    }

    // Set directory ownership and permissions (root:meshlink, 2775 = setgid)
    chown(&dir_str, "root", GROUP_NAME)?;
    chmod(&dir_str, "2775")?;
    actions.push(format!(
        "Set {dir_str} ownership to root:{GROUP_NAME} mode 2775"
    ));

    // Create config.toml placeholder if missing
    if !config_path.exists() {
        std::fs::write(&config_path, minimal_config_template())
            .context("creating config.toml")?;
        actions.push(format!("Created {config_str} (template)"));
    } else {
        actions.push(format!("{config_str} already exists (skipped creation)"));
    }

    // Set config file ownership and permissions (root:meshlink, 0660).
    // It holds the private key: never world-readable.
    chown(&config_str, "root", GROUP_NAME)?;
    chmod(&config_str, "0660")?;
    actions.push(format!(
        "Set {config_str} ownership to root:{GROUP_NAME} mode 0660"
    ));

    // Fix credentials.json permissions if it exists
    if creds_path.exists() {
        chown(&creds_str, "root", GROUP_NAME)?;
        chmod(&creds_str, "0660")?;
        actions.push(format!(
            "Set {creds_str} ownership to root:{GROUP_NAME} mode 0660"
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
    println!("Then run: sudo meshlink up --server <URL> --invite <CODE>");

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
     # Run: sudo meshlink up --server <URL> --invite <CODE>\n"
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
