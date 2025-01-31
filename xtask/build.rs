fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    vergen::EmitBuilder::builder().all_git().emit()?;
    Ok(())
}
