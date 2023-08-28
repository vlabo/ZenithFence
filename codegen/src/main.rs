use data_types::PacketInfo;
use serde_reflection::{Tracer, TracerConfig};

fn add_all_types(tracer: &mut Tracer) {
    // All types that require code generations.
    tracer.trace_simple_type::<PacketInfo>().unwrap();
    // Add more types here when needed.
}

fn main() {
    let mut tracer = Tracer::new(TracerConfig::default());
    add_all_types(&mut tracer);
    let registry = tracer.registry().unwrap();
    let config = serde_generate::CodeGeneratorConfig::new("kext_structs".to_string())
        .with_serialization(false);
    let generator = serde_generate::golang::CodeGenerator::new(&config);
    let mut source = Vec::new();
    generator.output(&mut source, &registry).unwrap();
    println!("{}", std::str::from_utf8(&source).unwrap());
}
