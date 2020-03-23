use std::process::Command;

fn main() {
    Command::new("make")
        .arg("libs")
        .current_dir("clibs")
        .spawn()
        .unwrap();
    println!("cargo:rustc-link-search=clibs/libs");
}
