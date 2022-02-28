test-server:
	@npx ganache -m "comfort expect symptom success relax hockey position catalog grab fall resist guitar" -v

fund-mpc-account:
	@cargo run -p web3-test-helpers --bin=fund-mpc-account

fmt:
	@cargo fmt --all

.PHONY: test-server fund-mpc-account fmt
