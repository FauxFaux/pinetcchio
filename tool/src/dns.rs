use std::collections::HashMap;

// 32-bit minimum please!
use cast::u32;

// `&'static str` references here are a big lie, but they're owned by the `Vec`.
// Rust currently cannot express this.
#[derive(Default)]
pub struct InternalResolver {
    ip_to_name: Vec<Box<str>>,
    name_to_ip: HashMap<&'static str, u32>,
}

impl InternalResolver {
    fn push(&mut self, boxed: Box<str>) -> u32 {
        let pos = u32(self.ip_to_name.len()).expect("TODO");
        // `hurt_reference` must be used only here
        self.name_to_ip.insert(hurt_reference(&boxed), pos);
        self.ip_to_name.push(boxed);
        pos
    }

    // TODO: string types / `entry()` is hard because we need a reference to the box, not the stack
    pub fn lookup<S: AsRef<str>>(&mut self, name: S) -> u32 {
        let name = name.as_ref();
        match self.name_to_ip.get(name) {
            Some(&val) => val,
            None => self.push(name.to_string().into_boxed_str()),
        }
    }
}

fn hurt_reference(val: &str) -> &'static str {
    unsafe { ::std::mem::transmute(val) }
}
