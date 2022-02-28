use anyhow::Result;

use web3_test_helpers::{fund_account, load_default_key_shares};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let (addr, _) = load_default_key_shares()?;
    // Ensure the MPC address has some funds to spend
    fund_account(addr, None).await?;
    Ok(())
}
