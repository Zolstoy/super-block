#[forbid(unsafe_code)]
pub mod error;
pub mod network;
pub mod server;
pub mod world;

pub type Result<T> = std::result::Result<T, crate::error::Error>;

#[cfg(test)]
mod tests_generate {
    use crate::world;

    #[test]
    fn case_01() {
        let chunk = world::generate_chunk();
    }
}
