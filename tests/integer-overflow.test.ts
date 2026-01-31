import * as anchor from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { assert } from "chai";
import BN from "bn.js";
import type { VulnerableIntegerOverflow } from "../target/types/vulnerable_integer_overflow";
import type { SecureIntegerOverflow } from "../target/types/secure_integer_overflow";

describe("Vulnerability: Integer Overflow / Underflow", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs
  const vulnerableProgram: anchor.Program<VulnerableIntegerOverflow> =
    anchor.workspace.VulnerableIntegerOverflow;
  const secureProgram: anchor.Program<SecureIntegerOverflow> =
    anchor.workspace.SecureIntegerOverflow;

  // Test accounts
  let owner: Keypair;
  let vaultVuln: PublicKey;
  let vaultSecure: PublicKey;

  // u64::MAX
  const U64_MAX = new BN("18446744073709551615");

  before(async () => {
    owner = Keypair.generate();

    // Airdrop SOL to owner
    const airdropAmount = 2 * anchor.web3.LAMPORTS_PER_SOL;
    const airdrop = await provider.connection.requestAirdrop(
      owner.publicKey,
      airdropAmount
    );
    await provider.connection.confirmTransaction(airdrop);

    // Derive PDAs
    [vaultVuln] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), owner.publicKey.toBuffer()],
      vulnerableProgram.programId
    );

    [vaultSecure] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), owner.publicKey.toBuffer()],
      secureProgram.programId
    );

    console.log("      Setup complete:");
    console.log("      Owner:", owner.publicKey.toBase58());
    console.log("      Vulnerable Vault PDA:", vaultVuln.toBase58());
    console.log("      Secure Vault PDA:", vaultSecure.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    it("initializes a vault", async () => {
      console.log("\n      1. Initializing vulnerable vault...");

      await vulnerableProgram.methods
        .initialize()
        .accounts({
          vault: vaultVuln,
          owner: owner.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc();

      const vaultData = await vulnerableProgram.account.vaultState.fetch(vaultVuln);
      assert.ok(vaultData.owner.equals(owner.publicKey), "Owner should match");
      assert.ok(vaultData.balance.toNumber() === 0, "Balance should be 0");
      console.log("      Vault initialized with balance:", vaultData.balance.toString());
    });

    it("deposit causes overflow: balance wraps around to a small number", async () => {
      console.log("\n      OVERFLOW EXPLOIT DEMONSTRATION:");

      // Step 1: Deposit a small amount first to give the vault a nonzero balance
      console.log("      1. Depositing 1000 to give vault a nonzero balance...");
      await vulnerableProgram.methods
        .deposit(new BN(1000))
        .accounts({
          vault: vaultVuln,
          owner: owner.publicKey,
        })
        .signers([owner])
        .rpc();

      let vaultData = await vulnerableProgram.account.vaultState.fetch(vaultVuln);
      console.log("      Vault balance after deposit:", vaultData.balance.toString());
      assert.ok(vaultData.balance.toNumber() === 1000, "Balance should be 1000");

      // Step 2: Deposit u64::MAX - this should cause overflow (1000 + u64::MAX wraps)
      console.log("\n      2. ATTACK: Depositing u64::MAX (18446744073709551615)...");
      console.log("         Expected: 1000 + u64::MAX wraps around to 999");

      await vulnerableProgram.methods
        .deposit(U64_MAX)
        .accounts({
          vault: vaultVuln,
          owner: owner.publicKey,
        })
        .signers([owner])
        .rpc();

      vaultData = await vulnerableProgram.account.vaultState.fetch(vaultVuln);
      console.log("      Vault balance after overflow:", vaultData.balance.toString());
      console.log("      VULNERABILITY CONFIRMED: Balance wrapped around!");

      // 1000 + u64::MAX = 999 (wraps around modulo 2^64)
      assert.ok(
        vaultData.balance.toNumber() === 999,
        "Balance should have wrapped to 999 (1000 + u64::MAX mod 2^64)"
      );
      console.log("      Balance is now 999 instead of a huge number - overflow occurred!");
    });

    it("withdraw causes underflow: balance wraps to a huge number", async () => {
      console.log("\n      UNDERFLOW EXPLOIT DEMONSTRATION:");

      // Current balance is 999 from the overflow above
      let vaultData = await vulnerableProgram.account.vaultState.fetch(vaultVuln);
      const currentBalance = vaultData.balance.toNumber();
      console.log("      Current balance:", currentBalance);

      // Withdraw more than the balance - this should cause underflow
      const withdrawAmount = new BN(1000);
      console.log("      ATTACK: Withdrawing", withdrawAmount.toString(), "from balance of", currentBalance);
      console.log("         Expected: 999 - 1000 wraps to u64::MAX");

      await vulnerableProgram.methods
        .withdraw(withdrawAmount)
        .accounts({
          vault: vaultVuln,
          owner: owner.publicKey,
        })
        .signers([owner])
        .rpc();

      vaultData = await vulnerableProgram.account.vaultState.fetch(vaultVuln);
      console.log("      Vault balance after underflow:", vaultData.balance.toString());
      console.log("      VULNERABILITY CONFIRMED: Balance wrapped to massive number!");

      // 999 - 1000 wraps to u64::MAX (18446744073709551615)
      assert.ok(
        vaultData.balance.toString() === U64_MAX.toString(),
        "Balance should have wrapped to u64::MAX"
      );
      console.log("      Attacker now has u64::MAX balance via underflow!");
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    it("initializes a vault", async () => {
      console.log("\n      1. Initializing secure vault...");

      await secureProgram.methods
        .initialize()
        .accounts({
          vault: vaultSecure,
          owner: owner.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc();

      const vaultData = await secureProgram.account.vaultState.fetch(vaultSecure);
      assert.ok(vaultData.owner.equals(owner.publicKey), "Owner should match");
      assert.ok(vaultData.balance.toNumber() === 0, "Balance should be 0");
      console.log("      Secure vault initialized with balance:", vaultData.balance.toString());
    });

    it("deposit correctly rejects overflow", async () => {
      console.log("\n      FIX DEMONSTRATION (Overflow):");

      // Step 1: Deposit a small amount first
      console.log("      1. Depositing 1000 to give vault a nonzero balance...");
      await secureProgram.methods
        .deposit(new BN(1000))
        .accounts({
          vault: vaultSecure,
          owner: owner.publicKey,
        })
        .signers([owner])
        .rpc();

      let vaultData = await secureProgram.account.vaultState.fetch(vaultSecure);
      console.log("      Vault balance:", vaultData.balance.toString());
      assert.ok(vaultData.balance.toNumber() === 1000, "Balance should be 1000");

      // Step 2: Try to deposit u64::MAX - should fail with overflow error
      console.log("\n      2. ATTACK ATTEMPT: Depositing u64::MAX...");

      let attackFailed = false;
      let errorMessage = "";

      try {
        await secureProgram.methods
          .deposit(U64_MAX)
          .accounts({
            vault: vaultSecure,
            owner: owner.publicKey,
          })
          .signers([owner])
          .rpc();

        assert.fail("Expected transaction to fail due to overflow, but it succeeded!");
      } catch (error: any) {
        attackFailed = true;
        errorMessage = error.toString();
        console.log("      FIX CONFIRMED: Overflow deposit rejected!");
        console.log("      Error:", errorMessage.substring(0, 120));
      }

      assert.ok(attackFailed, "Overflow deposit should have been rejected");

      // Verify balance unchanged
      vaultData = await secureProgram.account.vaultState.fetch(vaultSecure);
      assert.ok(vaultData.balance.toNumber() === 1000, "Balance should still be 1000");
      console.log("      Balance unchanged at:", vaultData.balance.toString());
    });

    it("withdraw correctly rejects underflow", async () => {
      console.log("\n      FIX DEMONSTRATION (Underflow):");

      // Current balance is 1000
      let vaultData = await secureProgram.account.vaultState.fetch(vaultSecure);
      const currentBalance = vaultData.balance.toNumber();
      console.log("      Current balance:", currentBalance);

      // Try to withdraw more than the balance - should fail with underflow error
      const withdrawAmount = new BN(2000);
      console.log("      ATTACK ATTEMPT: Withdrawing", withdrawAmount.toString(), "from balance of", currentBalance);

      let attackFailed = false;
      let errorMessage = "";

      try {
        await secureProgram.methods
          .withdraw(withdrawAmount)
          .accounts({
            vault: vaultSecure,
            owner: owner.publicKey,
          })
          .signers([owner])
          .rpc();

        assert.fail("Expected transaction to fail due to underflow, but it succeeded!");
      } catch (error: any) {
        attackFailed = true;
        errorMessage = error.toString();
        console.log("      FIX CONFIRMED: Underflow withdrawal rejected!");
        console.log("      Error:", errorMessage.substring(0, 120));
      }

      assert.ok(attackFailed, "Underflow withdrawal should have been rejected");

      // Verify balance unchanged
      vaultData = await secureProgram.account.vaultState.fetch(vaultSecure);
      assert.ok(vaultData.balance.toNumber() === 1000, "Balance should still be 1000");
      console.log("      Balance unchanged at:", vaultData.balance.toString());
    });
  });

  describe("Summary", () => {
    it("demonstrates the critical difference between vulnerable and secure implementations", () => {
      console.log("\n      VULNERABILITY SUMMARY:");
      console.log("      ");
      console.log("      VULNERABLE: Uses plain arithmetic (+ / -) with overflow-checks = false");
      console.log("         -> balance + u64::MAX wraps around (overflow)");
      console.log("         -> balance - amount wraps to huge number (underflow)");
      console.log("         -> Attacker can manipulate vault balance arbitrarily");
      console.log("      ");
      console.log("      SECURE: Uses checked_add / checked_sub with explicit error handling");
      console.log("         -> checked_add returns None on overflow -> error returned");
      console.log("         -> checked_sub returns None on underflow -> error returned");
      console.log("         -> Balance integrity is preserved");
      console.log("      ");
      console.log("      REAL-WORLD IMPACT:");
      console.log("         - Overflow: Attacker deposits huge amount, balance wraps to small value");
      console.log("         - Underflow: Attacker withdraws more than balance, gets u64::MAX balance");
      console.log("         - Either can drain funds from vaults/pools/reserves");
      console.log("      ");
      console.log("      KEY LESSON:");
      console.log("         Always use checked arithmetic (checked_add, checked_sub,");
      console.log("         checked_mul, checked_div) for any operation on token amounts,");
      console.log("         balances, or other critical numeric values.");
      console.log("         Never rely on overflow-checks = true in Cargo.toml alone -");
      console.log("         explicit checks make the intent clear and survive config changes.");
    });
  });
});
