use std::{
    env, fs,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::Local;
use handlebars::Handlebars;
use serde_json::json;
use zip::{write::FileOptions, ZipWriter};

static VERSION: [u8; 4] = include!("../../kext_interface/version.txt");
static LIB_PATH: &'static str = "./build/x86_64-pc-windows-msvc/release/driver.lib";

fn main() {
    build_driver();
    println!(
        "Building kext v{}-{}-{} #{}",
        VERSION[0], VERSION[1], VERSION[2], VERSION[3]
    );

    // Small CLI: default -> create folder; --zip -> create zip file
    let mut args = env::args().skip(1);
    let mut make_zip = false;
    let mut out: Option<PathBuf> = None;
    let mut with_bat = false; // when creating folder, optionally also write the bat script

    while let Some(a) = args.next() {
        match a.as_str() {
            "--zip" | "-z" => make_zip = true,
            "--out" | "-o" => {
                if let Some(p) = args.next() {
                    out = Some(PathBuf::from(p));
                }
            }
            "--with-bat" | "-b" => {
                with_bat = true;
            }
            _ => {
                // ignore unknown
            }
        }
    }

    let default_base = format!("kext_release_v{}-{}-{}", VERSION[0], VERSION[1], VERSION[2]);

    let out_path = match out {
        Some(p) => p,
        None => {
            if make_zip {
                PathBuf::from(format!("{}.zip", default_base))
            } else {
                PathBuf::from(default_base)
            }
        }
    };

    if make_zip {
        // ensure file has .zip extension
        let zip_path = if out_path.extension().is_none() {
            out_path.with_extension("zip")
        } else {
            out_path
        };
        create_release_zip(&zip_path);
        println!("Created zip: {}", zip_path.display());
    } else {
        create_release_dir(&out_path, with_bat);
        println!("Created release directory: {}", out_path.display());
    }
}

fn version_str() -> String {
    return format!(
        "{}.{}.{}.{}",
        VERSION[0], VERSION[1], VERSION[2], VERSION[3]
    );
}

fn build_driver() {
    let output = Command::new("cargo")
        .current_dir("../driver")
        .arg("build")
        .arg("--release")
        .args(["--target", "x86_64-pc-windows-msvc"])
        .args(["--target-dir", "../release/build"])
        .output()
        .unwrap();
    println!("{}", String::from_utf8(output.stderr).unwrap());
}

fn get_inf_content() -> String {
    let reg = Handlebars::new();
    let today = Local::now();
    reg.render_template(
        include_str!("../templates/ZenithFence64.inf"),
        &json!({"date": today.format("%m/%d/%Y").to_string(), "version": version_str()}),
    )
    .unwrap()
}

fn get_ddf_content() -> String {
    let reg = Handlebars::new();
    let version_file = format!("ZenithFence_v{}-{}-{}", VERSION[0], VERSION[1], VERSION[2]);
    reg.render_template(
        include_str!("../templates/ZenithFence.ddf"),
        &json!({"version_file": version_file}),
    )
    .unwrap()
}

fn get_build_cab_script_content() -> String {
    let reg = Handlebars::new();
    let version_file = format!("ZenithFence_v{}-{}-{}", VERSION[0], VERSION[1], VERSION[2]);

    reg
        .render_template(
            include_str!("../templates/build_cab.bat"),
            &json!({"sys_file": format!("{}.sys", version_file), "pdb_file": format!("{}.pdb", version_file), "lib_file": "driver.lib", "version_file": &version_file }),
        )
        .unwrap()
}

fn create_release_zip(zip_path: &Path) {
    let file = File::create(zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let version_file = format!("ZenithFence_v{}-{}-{}", VERSION[0], VERSION[1], VERSION[2]);

    zip.add_directory("cab", FileOptions::default()).unwrap();
    // Write driver.lib
    write_lib_file_zip(&mut zip);
    // Write ddf file
    write_to_zip(
        &mut zip,
        &format!("{}.ddf", version_file),
        get_ddf_content(),
    );
    // Write build cab script
    write_to_zip(&mut zip, "build_cab.bat", get_build_cab_script_content());

    // Write inf file
    write_to_zip(
        &mut zip,
        &format!("cab/{}.inf", version_file),
        get_inf_content(),
    );

    zip.finish().unwrap();
}

fn create_release_dir(dir_path: &Path, with_bat: bool) {
    // create base dir and cab subdir
    fs::create_dir_all(dir_path).unwrap();
    let cab_dir = dir_path.join("cab");
    fs::create_dir_all(&cab_dir).unwrap();

    // copy driver.lib
    let dest_lib = dir_path.join("driver.lib");
    fs::copy(LIB_PATH, &dest_lib).unwrap();

    let version_file = format!("ZenithFence_v{}-{}-{}", VERSION[0], VERSION[1], VERSION[2]);

    // write ddf
    let ddf_path = dir_path.join(format!("{}.ddf", version_file));
    fs::write(ddf_path, get_ddf_content()).unwrap();

    // write build_cab.bat (optional)
    if with_bat {
        let build_bat = dir_path.join("build_cab.bat");
        fs::write(build_bat, get_build_cab_script_content()).unwrap();
    }

    // write inf into cab/
    let inf_path = cab_dir.join(format!("{}.inf", version_file));
    fs::write(inf_path, get_inf_content()).unwrap();

    // Link driver.lib into a .sys and produce .pdb, then move them into cab/
    // This mirrors the steps in build_cab.bat but runs them automatically.
    let sys_file = format!("{}.sys", version_file);
    let pdb_file = format!("{}.pdb", version_file);

    // Run link.exe in the output directory
    let link_status = Command::new("link.exe")
        .current_dir(dir_path)
        .arg(format!("/OUT:{}", sys_file))
        .arg("/RELEASE")
        .arg("/DEBUG")
        .arg("/NOLOGO")
        .arg("/NXCOMPAT")
        .arg("/NODEFAULTLIB")
        .arg("/SUBSYSTEM:NATIVE")
        .arg("/DRIVER")
        .arg("/DYNAMICBASE")
        .arg("/MANIFEST:NO")
        .arg("/PDBALTPATH:none")
        .arg("/MACHINE:X64")
        .arg("/OPT:REF,ICF")
        .arg("/SUBSYSTEM:NATIVE,6.01")
        .arg("/ENTRY:FxDriverEntry")
        .arg("/MERGE:.edata=.rdata;_TEXT=.text;_PAGE=PAGE")
        .arg("/MERGE:.rustc=.data")
        .arg("/INTEGRITYCHECK")
        .arg("driver.lib")
        .output()
        .expect(
            "failed to run link.exe; ensure Visual Studio build tools are installed and in PATH",
        );

    println!(
        "link stdout: {}",
        String::from_utf8_lossy(&link_status.stdout)
    );
    println!(
        "link stderr: {}",
        String::from_utf8_lossy(&link_status.stderr)
    );

    // Move produced files into cab directory (link outputs to dir_path)
    let produced_sys = dir_path.join(&sys_file);
    let produced_pdb = dir_path.join(&pdb_file);
    if produced_sys.exists() {
        fs::rename(&produced_sys, cab_dir.join(&sys_file)).unwrap();
    }
    if produced_pdb.exists() {
        fs::rename(&produced_pdb, cab_dir.join(&pdb_file)).unwrap();
    }

    // Run MakeCab to create the .cab based on the .ddf we wrote
    let ddf_name = format!("{}.ddf", version_file);
    let makecab_status = Command::new("MakeCab")
        .current_dir(dir_path)
        .arg("/f")
        .arg(&ddf_name)
        .output()
        .expect("failed to run MakeCab; ensure MakeCab.exe is available in PATH");

    println!(
        "makecab stdout: {}",
        String::from_utf8_lossy(&makecab_status.stdout)
    );
    println!(
        "makecab stderr: {}",
        String::from_utf8_lossy(&makecab_status.stderr)
    );

    // Move produced .cab from disk1\ to root and cleanup
    let disk1_dir = dir_path.join("disk1");
    let produced_cab = disk1_dir.join(format!("{}.cab", version_file));
    if produced_cab.exists() {
        fs::rename(
            &produced_cab,
            dir_path.join(format!("{}.cab", version_file)),
        )
        .unwrap();
    }
    // remove disk1 dir if exists
    if disk1_dir.exists() {
        fs::remove_dir_all(disk1_dir).ok();
    }

    // remove setup.inf and setup.rpt if created
    let setup_inf = dir_path.join("setup.inf");
    let setup_rpt = dir_path.join("setup.rpt");
    if setup_inf.exists() {
        fs::remove_file(setup_inf).ok();
    }
    if setup_rpt.exists() {
        fs::remove_file(setup_rpt).ok();
    }
}

fn write_to_zip(zip: &mut ZipWriter<File>, filename: &str, content: String) {
    zip.start_file(filename, FileOptions::default()).unwrap();
    zip.write(&content.into_bytes()).unwrap();
}

fn write_lib_file_zip(zip: &mut ZipWriter<File>) {
    zip.start_file("driver.lib", FileOptions::default())
        .unwrap();
    let mut driver_file = File::open(LIB_PATH).unwrap();
    std::io::copy(&mut driver_file, zip).unwrap();
}
