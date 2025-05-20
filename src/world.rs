use noise::utils::{NoiseMap, PlaneMapBuilder};
use noise::{core::perlin::perlin_2d, permutationtable::PermutationTable};

fn generate_noise_map() -> NoiseMap {
    let hasher = PermutationTable::new(0);
    PlaneMapBuilder::new_fn(|point| perlin_2d(point.into(), &hasher))
        .set_size(1024, 1024)
        .set_x_bounds(-5.0, 5.0)
        .set_y_bounds(-5.0, 5.0)
        .build()
}

#[derive(Clone)]
pub enum Block {
    Dirt,
    Stone,
}

pub struct Chunk {
    blocks: Vec<Block>,
}

impl Chunk {
    pub fn at(&self, x: usize, y: usize) -> Block {
        self.blocks.get(y * 1014 + x).unwrap().clone()
    }
}

pub fn generate_chunk() -> Chunk {
    let noise_map = generate_noise_map();

    Chunk {
        blocks: noise_map
            .iter()
            .map(|x| if x < 0 { Block::Dirt } else { Block::Stone })
            .collect(),
    }
}
