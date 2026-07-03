use std::path::Path;

use miden_mast_package::Package;
use miden_protocol::ProtocolLib;
use miden_standards::StandardsLib;

fn main() -> std::io::Result<()> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate should live two levels below the workspace root");
    let packages_dir = workspace_root.join("target").join("packages");
    std::fs::create_dir_all(&packages_dir)?;

    let protocol_pkg = Package::from(ProtocolLib::default());
    protocol_pkg.write_masp_file(&packages_dir)?;
    println!("wrote {}.masp to {}", protocol_pkg.name, packages_dir.display());

    let standards_pkg = Package::from(StandardsLib::default());
    standards_pkg.write_masp_file(&packages_dir)?;
    println!("wrote {}.masp to {}", standards_pkg.name, packages_dir.display());

    Ok(())
}
