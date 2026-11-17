// `sqlx::migrate!` embeds the migration files into the binary at compile time.
// Cargo does not notice a new migration file by itself, so without this a
// build that only adds a migration can reuse the old compiled app and never
// run the new migration. This makes any change in the migrations folder
// (a new, edited or removed file) force the app to be rebuilt.
fn main() {
    // Same folder the `sqlx::migrate!` call in src/container.rs reads,
    // relative to this crate.
    println!("cargo:rerun-if-changed=../../migrations");
}
