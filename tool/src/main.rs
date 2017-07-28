#[macro_use]
extern crate error_chain;
extern crate namespace;

mod errors;

use errors::*;

fn run() -> Result<()> {
    namespace::prepare()?;
    Ok(())
}

quick_main!(run);
