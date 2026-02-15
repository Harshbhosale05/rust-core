use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/offline_token.proto"], &["proto/"])?;
    Ok(())
}
