rustc -O injector.rs
rustc -O --crate-type=cdylib -Clink-arg=ssl_inspector.lib injectee.rs
