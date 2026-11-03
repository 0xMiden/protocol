mod component;
mod config;
mod policy;

pub use component::AuthHotColdGuardian;
pub use config::{
    AuthHotColdGuardianConfig,
    BLOCKS_PER_HOUR,
    DEFAULT_MIN_DELAY_BLOCKS,
    DEFAULT_THRESHOLD,
    HotColdDelayConfig,
    MAX_NUM_HOT_KEYS,
    MIN_DELAY_FLOOR_BLOCKS,
    NUM_USER_CATEGORIES,
};
pub use policy::HotColdPolicy;
