use anyhow::Result;

/// A provider independent translator
pub trait AddressTranslator {
    /// Reflush the translator cache(if any)
    fn populate(&mut self) -> Result<()> {
        Ok(())
    }

    /// Translate virtual address to physical address
    fn translate(&self, virt: u64) -> Result<u64>;
}