fn main() {
    let mut attrs = tauri_build::Attributes::new();

    // Release builds always run elevated so every process's path and signature
    // can be inspected. Debug builds stay as-invoker so `cargo tauri dev` works
    // from a normal terminal (the UI shows when it is running without admin).
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        attrs = attrs.windows_attributes(
            tauri_build::WindowsAttributes::new().app_manifest(include_str!("admin.manifest")),
        );
    }

    tauri_build::try_build(attrs).expect("failed to run tauri build script");
}
