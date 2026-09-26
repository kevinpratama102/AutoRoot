/*
Miscellaneous helper functions.
*/
use anyhow::Result;
use std::fs;
use std::path::PathBuf;

/*
Check if the host's kernel version to see if it is vulnerable.
Basing version check on https://securitylabs.datadoghq.com/articles/dirty-pipe-vulnerability-overview-and-remediation/
*/
pub fn is_kernel_vuln() -> Result<bool, anyhow::Error> {
    // Read version string from /proc/version
    let proc_version = fs::read_to_string("/proc/version")?;

    // Split to get just the kernel version
    let release_strings = proc_version.split("Linux version ").collect::<Vec<&str>>()[1]
        .split(" ")
        .collect::<Vec<&str>>()[0]
        .split("-")
        .collect::<Vec<&str>>();
    let kernel_version = String::from(release_strings[0]) + "-" + release_strings[1];

    println!("[-] Kernel version: {}", kernel_version);

    // Split version string to check major and minor versions
    let versions: Vec<String> = kernel_version.split(".").map(|x| String::from(x)).collect();
    if versions[0].parse::<i32>().unwrap() != 5 {
        // Must be Kernel 5.x
        return Ok(false);
    }
    if versions[1].parse::<i32>().unwrap() < 8 || versions[1].parse::<i32>().unwrap() > 16 {
        return Ok(false);
    }

    // Check patch level
    let patch_level = versions[2].split("-").collect::<Vec<&str>>()[0]
        .parse::<i32>()
        .unwrap();
    let is_vuln = match versions[1].parse::<i32>().unwrap() {
        16 => patch_level < 11,
        15 => patch_level < 25,
        10 => patch_level < 102,
        _ => true,
    };
    Ok(is_vuln)
}

/*
Copy a given file to /tmp. Used to backup a file before overwriting.
*/
pub fn backup_file(target: &PathBuf) -> Result<(), anyhow::Error> {
    let mut new_path = PathBuf::new();
    new_path.push("/tmp");
    new_path.push(target.file_name().unwrap());

    fs::copy(target, &new_path)?;

    println!(
        "[-] Backed up {} to {}",
        target.to_str().unwrap(),
        new_path.to_str().unwrap()
    );
    Ok(())
}
