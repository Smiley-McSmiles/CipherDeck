use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorMode {
    RandomChars,
    Passphrase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthLevel {
    Weak,
    Fair,
    Good,
    Strong,
    VeryStrong,
}

impl StrengthLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Weak => "Weak",
            Self::Fair => "Fair",
            Self::Good => "Good",
            Self::Strong => "Strong",
            Self::VeryStrong => "Very Strong",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PasswordGenConfig {
    pub mode: GeneratorMode,
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub word_count: usize,
    pub separator: String,
    pub capitalize_words: bool,
    pub append_number: bool,
}

impl Default for PasswordGenConfig {
    fn default() -> Self {
        Self {
            mode: GeneratorMode::RandomChars,
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            word_count: 5,
            separator: "-".to_string(),
            capitalize_words: true,
            append_number: true,
        }
    }
}

pub struct GeneratedPassword {
    pub password: Zeroizing<String>,
    pub entropy_bits: f64,
    pub strength: StrengthLevel,
}

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const UPPER_NO_AMB: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const LOWER_NO_AMB: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const DIGITS_NO_AMB: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

const WORDS: &[&str] = &[
    "acorn", "amber", "anchor", "anvil", "apple", "arctic", "arrow", "aspen",
    "atlas", "autumn", "badge", "bamboo", "banjo", "barley", "barrel", "basalt",
    "beacon", "beaver", "breeze", "briar", "bridge", "bronze", "brook", "canyon",
    "carbon", "cedar", "chalet", "cherry", "cinder", "citadel", "clover", "cobalt",
    "comet", "compass", "copper", "coral", "cougar", "crater", "creek", "crimson",
    "crystal", "cypress", "dagger", "dawn", "delta", "desert", "diamond", "dolphin",
    "dragon", "drift", "eagle", "echo", "eclipse", "elder", "emerald", "ember",
    "falcon", "fern", "fjord", "flint", "forest", "forge", "fossil", "frost",
    "galaxy", "garnet", "geyser", "glacier", "granite", "gravel", "griffin", "grove",
    "harbor", "harvest", "haven", "hawk", "hazel", "heather", "helmet", "heron",
    "horizon", "hunter", "indigo", "iris", "island", "ivory", "jade", "jaguar",
    "jasper", "juniper", "kestrel", "kettle", "lantern", "larch", "laurel", "lava",
    "ledger", "lichen", "lilac", "linden", "lotus", "lunar", "lynx", "magnet",
    "maple", "marble", "meadow", "mercury", "mesa", "meteor", "mineral", "mirage",
    "monarch", "monsoon", "mosaic", "moss", "mountain", "nebula", "nectar", "needle",
    "noble", "north", "nutmeg", "oak", "oasis", "obsidian", "ocean", "olive",
    "onyx", "opal", "orbit", "orchid", "oriole", "osprey", "otter", "outpost",
    "owl", "paddle", "panther", "parchment", "pebble", "pelican", "pepper", "phoenix",
    "pioneer", "planet", "platinum", "plume", "polar", "poplar", "prairie", "prism",
    "pulsar", "quartz", "quiver", "rabbit", "radish", "raptor", "raven", "redwood",
    "reef", "ridge", "ripple", "river", "robin", "rocket", "ruby", "saffron",
    "sage", "salmon", "sapphire", "saturn", "scarlet", "schooner", "sequoia", "shadow",
    "shale", "shelter", "shield", "sierra", "silver", "skylark", "slate", "solstice",
    "sparrow", "spectrum", "spruce", "starlight", "stone", "storm", "stream", "summit",
    "sunbeam", "sunset", "sycamore", "talisman", "tamarack", "tangerine", "tempest", "thistle",
    "thunder", "timber", "topaz", "torch", "torrent", "trail", "trident", "tundra",
    "tulip", "turret", "umbra", "unicorn", "valley", "velvet", "venture", "vermilion",
    "vertex", "vesper", "violet", "viper", "volcano", "voyager", "walnut", "warden",
    "waterfall", "whisper", "wildflower", "willow", "winter", "wolf", "wren", "zenith",
    "zephyr", "zinc", "zircon",
];

pub fn strength_from_entropy(bits: f64) -> StrengthLevel {
    if bits < 40.0 {
        StrengthLevel::Weak
    } else if bits < 60.0 {
        StrengthLevel::Fair
    } else if bits < 80.0 {
        StrengthLevel::Good
    } else if bits < 105.0 {
        StrengthLevel::Strong
    } else {
        StrengthLevel::VeryStrong
    }
}

pub fn estimate_entropy_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace());
    let has_space = password.chars().any(|c| c.is_whitespace());

    let mut pool = 0usize;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 26;
    }
    if has_space {
        pool += 1;
    }
    if pool == 0 {
        pool = 64;
    }
    (password.chars().count() as f64) * (pool as f64).log2()
}

pub fn generate_password(cfg: &PasswordGenConfig) -> GeneratedPassword {
    match cfg.mode {
        GeneratorMode::RandomChars => generate_random_chars(cfg),
        GeneratorMode::Passphrase => generate_passphrase(cfg),
    }
}

fn generate_random_chars(cfg: &PasswordGenConfig) -> GeneratedPassword {
    let length = cfg.length.clamp(4, 128);
    let mut pools: Vec<&[u8]> = Vec::new();
    if cfg.uppercase {
        pools.push(if cfg.exclude_ambiguous {
            UPPER_NO_AMB
        } else {
            UPPER
        });
    }
    if cfg.lowercase {
        pools.push(if cfg.exclude_ambiguous {
            LOWER_NO_AMB
        } else {
            LOWER
        });
    }
    if cfg.digits {
        pools.push(if cfg.exclude_ambiguous {
            DIGITS_NO_AMB
        } else {
            DIGITS
        });
    }
    if cfg.symbols {
        pools.push(SYMBOLS);
    }
    if pools.is_empty() {
        pools.push(LOWER);
    }

    let combined: Vec<u8> = pools.iter().flat_map(|p| p.iter().copied()).collect();
    let mut chars: Vec<u8> = Vec::with_capacity(length);
    let mut rng = OsRng;

    // Guarantee at least one character from each enabled class
    for pool in &pools {
        if chars.len() < length {
            let idx = rng.gen_range(0..pool.len());
            chars.push(pool[idx]);
        }
    }
    while chars.len() < length {
        let idx = rng.gen_range(0..combined.len());
        chars.push(combined[idx]);
    }
    chars.shuffle(&mut rng);

    let pw = String::from_utf8(chars).unwrap_or_default();
    let entropy_bits = (length as f64) * (combined.len() as f64).log2();
    GeneratedPassword {
        password: Zeroizing::new(pw),
        entropy_bits,
        strength: strength_from_entropy(entropy_bits),
    }
}

fn generate_passphrase(cfg: &PasswordGenConfig) -> GeneratedPassword {
    let count = cfg.word_count.clamp(3, 12);
    let mut rng = OsRng;
    let mut parts: Vec<String> = Vec::with_capacity(count + 1);
    for _ in 0..count {
        let idx = rng.gen_range(0..WORDS.len());
        let word = WORDS[idx];
        if cfg.capitalize_words {
            let mut c = word.chars();
            let cap = match c.next() {
                Some(first) => first.to_uppercase().to_string() + c.as_str(),
                None => String::new(),
            };
            parts.push(cap);
        } else {
            parts.push(word.to_string());
        }
    }
    let mut entropy_bits = (count as f64) * (WORDS.len() as f64).log2();
    if cfg.append_number {
        let num = rng.gen_range(10..100);
        if let Some(last) = parts.last_mut() {
            last.push_str(&num.to_string());
        }
        entropy_bits += (90.0_f64).log2();
    }
    let pw = parts.join(&cfg.separator);
    GeneratedPassword {
        password: Zeroizing::new(pw),
        entropy_bits,
        strength: strength_from_entropy(entropy_bits),
    }
}
