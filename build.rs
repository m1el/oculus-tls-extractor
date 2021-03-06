use std::error::Error;

#[cfg(feature="build-ssl-lib")]
mod build_ssl_lib {
    use std::error::Error;
    use std::fs::File;
    use std::io;
    use std::path::Path;
    use std::process::{self, Command};

    /// Check if a command is working and returning the expected results.
    fn check_output(command: &str, args: &[&str],
                     expected: &[&str]) -> Option<()> {
        // Invoke the command
        let result = Command::new(command).args(args).output().ok()?;

        // Check if the command was successful
        if !result.status.success() { return None; }

        // Convert the stdout bytes to a string
        let stdout = std::str::from_utf8(&result.stdout).ok()?;

        // Make sure `stdout` contains everything we expected
        if expected.iter().all(|x| stdout.contains(x)) {
            Some(())
        } else {
            None
        }
    }

    /// Check if a command has returned successfully
    fn check_status(command: &str, args: &[&str], dir: &str, err: &'static str)
        -> Result<(), Box<dyn Error>>
    {
        // Invoke the command
        if Command::new(command).args(args).current_dir(dir)
            .status()?.success() {
            Ok(())
        } else {
            Err(err)?
        }
    }

    /// URL to OpenSSL git
    const OPENSSL_GIT: &str = "https://github.com/openssl/openssl.git";
    /// Directory for OpenSSL to check out to
    const OPENSSL_DIR: &str = "openssl";
    /// Specific OpenSSL version to use
    const OPENSSL_VERSION: &str = "OpenSSL_1_0_2o";
    /// Path to patch which is applied to OpenSSL,
    /// allowing us to build the inspector lib
    const OPENSSL_PATCH: &str = "ssl_inspector.patch";

    pub fn do_build() -> Result<(), Box<dyn Error>> {
        check_output("git", &["--version"], &["git"])
            .ok_or("git needs to be visible in $PATH to build OpenSSL")?;
        check_output("perl", &["--version"], &["perl 5"])
            .ok_or("Perl needs to be present to configure and build OpenSSL")?;
        check_output("nmake", &["/?"], &["NMAKE"])
            .ok_or("Visual Studio environment is expected")?;

        if !Path::new(OPENSSL_DIR).is_dir() {
            if !Command::new("git").args(&["clone", OPENSSL_GIT, OPENSSL_DIR])
                .status()?.success() {
                return Err("Failed to clone OpenSSL git.")?;
            }
        }

        // Check out a specific version of OpenSSL
        check_status("git", &["checkout", "-f", OPENSSL_VERSION], OPENSSL_DIR,
                     "Failed to check out the required version. \
                     (checking out specific commit)")?;
        // Also check out all files in case there were changes
        check_status("git", &["checkout", "-f", "--", "."], OPENSSL_DIR,
                     "Failed to check out the required version. \
                     (checking out files)")?;

        let mut file = File::open(OPENSSL_PATCH)?;
        // Apply the patch to the OpenSSL makefile
        let mut process = Command::new("git").args(&["apply"])
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::null())
            .current_dir(OPENSSL_DIR)
            .spawn()?;

        // Pass the patch to stdin of `git apply`
        io::copy(&mut file, process.stdin.as_mut().unwrap())?;
        if !process.wait()?.success() {
            return Err("Failed to apply the patch.")?;
        }

        // Configure OpenSSL
        check_status("perl", &["Configure", "VC-WIN64A"], OPENSSL_DIR,
                     "Failed to configure OpenSSL.")?;
        // Generate Makefile for nmake
        check_status("cmd.exe", &["/C", "ms\\do_win64a.bat"], OPENSSL_DIR,
                     "Failed to run do_win64a.bat")?;
        // Build ssl_inspector static library
        check_status("nmake", &["-nologo", "-f", "ms\\nt.mak", "ssl_inspector"],
                     OPENSSL_DIR, "Failed to run nmake")?;

        Ok(())
    }
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(feature="build-ssl-lib")]
    build_ssl_lib::do_build()?;

    println!("cargo:rustc-link-lib=static=ssl_inspector");
    Ok(())
}
