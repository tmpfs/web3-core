//! Utility to generate BIP-39 passphrase mnemonics.
//!
//! Word count must be 12, 18 or 24.
use bip39::{Language, Mnemonic};
use std::str::FromStr;
use thiserror::Error;

/// Error thrown generating a mnemonic phrase.
#[derive(Debug, Error)]
pub enum PhraseError {
    /// Error thrown when the word count is invalid.
    #[error("word count must be 12, 18 or 24")]
    WordCount,
    /// Error thrown generating the bip39 mnemonic.
    #[error(transparent)]
    Bip39(#[from] bip39::Error),
    /// Error thrown parsing an integer.
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
}

/// Type for generating mnemonic phrases.
pub struct MnemonicPhrase {}

impl MnemonicPhrase {
    /// Generate a BIP-39 `Mnemonic` in the given language.
    pub fn mnemonic_in(
        language: Language,
        word_count: WordCount,
    ) -> Result<Mnemonic, PhraseError> {
        let word_count: u16 = word_count.into();
        Ok(Mnemonic::generate_in(language, word_count as usize)?)
    }

    /// Generate a `String` of BIP-39 passphrase words in the given language.
    pub fn words_in(
        language: Language,
        word_count: WordCount,
    ) -> Result<String, PhraseError> {
        Ok(format!(
            "{}",
            MnemonicPhrase::mnemonic_in(language, word_count)?
        ))
    }

    /// Generate a `String` of BIP-39 passphrase words in English.
    pub fn words(word_count: WordCount) -> Result<String, PhraseError> {
        MnemonicPhrase::words_in(Language::English, word_count)
    }
}

/// Variants for the number of words supported by
/// the BIP-39 mnemonic generation algorithm.
#[derive(Debug, Copy, Clone)]
pub enum WordCount {
    /// Short number of words.
    Short(u16),
    /// Medium number of words.
    Medium(u16),
    /// Long number of words.
    Long(u16),
}

impl WordCount {
    /// Short word count (12).
    pub fn short() -> Self {
        WordCount::Short(12)
    }

    /// Medium word count (18).
    pub fn medium() -> Self {
        WordCount::Medium(18)
    }

    /// Long word count (24).
    pub fn long() -> Self {
        WordCount::Long(24)
    }
}

impl Default for WordCount {
    fn default() -> Self {
        Self::Short(12)
    }
}

impl From<WordCount> for u16 {
    fn from(value: WordCount) -> u16 {
        match value {
            WordCount::Short(value)
            | WordCount::Medium(value)
            | WordCount::Long(value) => value,
        }
    }
}

impl FromStr for WordCount {
    type Err = PhraseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value: u16 = s.parse()?;
        WordCount::try_from(value)
    }
}

impl TryFrom<u16> for WordCount {
    type Error = PhraseError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            12 => Ok(WordCount::Short(value)),
            18 => Ok(WordCount::Medium(value)),
            24 => Ok(WordCount::Long(value)),
            _ => Err(PhraseError::WordCount),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use bip39::Language;

    #[test]
    fn generate_passphrase() -> Result<()> {
        let word_count: WordCount = Default::default();
        let passphrase =
            MnemonicPhrase::mnemonic_in(Language::English, word_count)?;
        let words = format!("{}", passphrase);
        let items: Vec<&str> = words.split(" ").collect();
        let count: u16 = word_count.into();
        assert_eq!(count as usize, items.len());
        Ok(())
    }
}
