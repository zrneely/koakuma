#[cfg(feature = "gui")]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_manifest_file("./manifest.xml");
    res.compile().unwrap();
}

#[cfg(not(feature = "gui"))]
fn main() {
    // Do nothing
}
