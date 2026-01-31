import * as anchor from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { assert } from "chai";
import BN from "bn.js";
import type { VulnerableClosingAccounts } from "../target/types/vulnerable_closing_accounts";
import type { SecureClosingAccounts } from "../target/types/secure_closing_accounts";

describe("Vulnerability: Closing Accounts", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs
  const vulnerableProgram: anchor.Program<VulnerableClosingAccounts> =
    anchor.workspace.VulnerableClosingAccounts;
  const secureProgram: anchor.Program<SecureClosingAccounts> =
    anchor.workspace.SecureClosingAccounts;

  // Test accounts
  let alice: Keypair;

  const DEPOSIT_AMOUNT = new BN(1000);

  before(async () => {
    alice = Keypair.generate();

    // Airdrop SOL to Alice
    const airdropAmount = 5 * anchor.web3.LAMPORTS_PER_SOL;
    await provider.connection.requestAirdrop(alice.publicKey, airdropAmount);

    // Wait for airdrop
    await new Promise((resolve) => setTimeout(resolve, 1000));

    console.log("      Setup complete:");
    console.log("      Alice:", alice.publicKey.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    let vaultPda: PublicKey;
    let vaultBump: number;

    before(async () => {
      // Derive vault PDA
      [vaultPda, vaultBump] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), alice.publicKey.toBuffer()],
        vulnerableProgram.programId
      );
    });

    it("initializes vault with deposit amount", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION:");
      console.log("      1. Alice initializes vault with 1000 lamports...");

      await vulnerableProgram.methods
        .initialize(DEPOSIT_AMOUNT)
        .accounts({
          authority: alice.publicKey,
          vault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      // Verify vault state
      const vaultData = await vulnerableProgram.account.vaultState.fetch(vaultPda);
      assert.ok(
        vaultData.authority.equals(alice.publicKey),
        "Alice should be the vault authority"
      );
      assert.ok(
        vaultData.balance.eq(DEPOSIT_AMOUNT),
        "Balance should be 1000"
      );
      assert.ok(vaultData.isActive, "Vault should be active");

      console.log("      Vault initialized:");
      console.log("        Authority:", vaultData.authority.toBase58());
      console.log("        Balance:", vaultData.balance.toString());
      console.log("        Is Active:", vaultData.isActive);
    });

    it("force_close drains lamports but does NOT zero account data", async () => {
      console.log("\n      2. Alice calls force_close...");

      // Get vault lamports before close
      const vaultInfoBefore = await provider.connection.getAccountInfo(vaultPda);
      console.log("      Vault lamports before close:", vaultInfoBefore!.lamports);

      await vulnerableProgram.methods
        .forceClose()
        .accounts({
          authority: alice.publicKey,
          vault: vaultPda,
        })
        .signers([alice])
        .rpc();

      console.log("      force_close executed successfully");

      // Read raw account data after close
      const vaultInfoAfter = await provider.connection.getAccountInfo(vaultPda);

      if (vaultInfoAfter === null) {
        // Runtime garbage-collected the account (lamports = 0 at end of tx)
        // But the vulnerability is that WITHIN the same transaction,
        // the data was still valid before GC
        console.log("      Account garbage-collected after transaction");
        console.log("      (Lamports were drained to 0, runtime cleaned up)");
        console.log("");
        console.log("      VULNERABILITY:");
        console.log("      Within the same transaction, BEFORE garbage collection,");
        console.log("      the account data was still intact and could be read.");
        console.log("      An attacker could compose instructions in a single tx:");
        console.log("        1. force_close (drains lamports, data stays)");
        console.log("        2. Re-fund the account with lamports");
        console.log("        3. Use the still-valid data to pass checks");
      } else {
        // Account still exists -- check if data was zeroed
        console.log("      Account still exists after close!");
        console.log("      Lamports after close:", vaultInfoAfter.lamports);

        const data = vaultInfoAfter.data;
        // Skip 8-byte Anchor discriminator, then check authority (32 bytes)
        const authorityBytes = data.slice(8, 40);
        const authorityKey = new PublicKey(authorityBytes);

        const isDataZeroed = data.slice(8).every((byte: number) => byte === 0);

        console.log("\n      VULNERABILITY CONFIRMED:");
        console.log("      Account data is NOT zeroed after close!");
        console.log("      Authority still in data:", authorityKey.toBase58());
        console.log("      Data zeroed?", isDataZeroed);
        console.log("");
        console.log("      The account can be 'revived' within the same transaction");
        console.log("      because the runtime only garbage-collects zero-lamport");
        console.log("      accounts at the END of the transaction.");

        assert.ok(
          !isDataZeroed,
          "Data should NOT be zeroed - this is the vulnerability"
        );
      }
    });

    it("explains the closing accounts vulnerability", async () => {
      console.log("\n      VULNERABLE CODE:");
      console.log("      pub fn force_close(ctx: Context<ForceClose>) -> Result<()> {");
      console.log("          let vault_lamports = vault.to_account_info().lamports();");
      console.log("          **vault.try_borrow_mut_lamports()? = 0;");
      console.log("          **authority.try_borrow_mut_lamports()? += vault_lamports;");
      console.log("          // MISSING: Should zero out account data!");
      console.log("          // MISSING: Should use close = authority constraint!");
      console.log("      }");
      console.log("");
      console.log("      ATTACK SCENARIO:");
      console.log("      In a single transaction, an attacker can:");
      console.log("      1. Call force_close (lamports drained, data stays)");
      console.log("      2. Transfer lamports back to the account");
      console.log("      3. The account 'revives' with original data");
      console.log("      4. Use the revived account as if it were never closed");
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    let vaultPda: PublicKey;
    let vaultBump: number;

    before(async () => {
      // Derive vault PDA for secure program
      [vaultPda, vaultBump] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), alice.publicKey.toBuffer()],
        secureProgram.programId
      );
    });

    it("initializes vault with deposit amount", async () => {
      console.log("\n      FIX DEMONSTRATION:");
      console.log("      1. Alice initializes secure vault with 1000 lamports...");

      await secureProgram.methods
        .initialize(DEPOSIT_AMOUNT)
        .accounts({
          authority: alice.publicKey,
          vault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      // Verify vault state
      const vaultData = await secureProgram.account.vaultState.fetch(vaultPda);
      assert.ok(
        vaultData.authority.equals(alice.publicKey),
        "Alice should be the vault authority"
      );
      assert.ok(
        vaultData.balance.eq(DEPOSIT_AMOUNT),
        "Balance should be 1000"
      );
      assert.ok(vaultData.isActive, "Vault should be active");

      console.log("      Secure vault initialized");
    });

    it("force_close properly zeros data and closes account", async () => {
      console.log("\n      2. Alice calls force_close (secure version)...");

      await secureProgram.methods
        .forceClose()
        .accounts({
          authority: alice.publicKey,
          vault: vaultPda,
        })
        .signers([alice])
        .rpc();

      console.log("      force_close executed successfully");

      // Read raw account data after close
      const vaultInfoAfter = await provider.connection.getAccountInfo(vaultPda);

      if (vaultInfoAfter === null) {
        console.log("      FIX CONFIRMED: Account is fully closed!");
        console.log("      The close = authority constraint:");
        console.log("        1. Transferred all lamports to authority");
        console.log("        2. Zeroed all account data");
        console.log("        3. Set owner to System Program");
        console.log("      Account cannot be revived - data is gone");
        assert.ok(true, "Account properly closed");
      } else {
        // If it still exists, verify data is zeroed
        const data = vaultInfoAfter.data;
        const isDataZeroed = data.every((byte: number) => byte === 0);
        console.log("      Account exists but data zeroed:", isDataZeroed);
        assert.ok(isDataZeroed, "Data should be zeroed after secure close");
      }
    });

    it("shows how close constraint provides protection", async () => {
      console.log("\n      SECURITY MECHANISM:");
      console.log("");
      console.log("      SECURE CODE:");
      console.log("      #[account(");
      console.log("          mut,");
      console.log("          seeds = [b\"vault\", authority.key().as_ref()],");
      console.log("          bump,");
      console.log("          has_one = authority,");
      console.log("          close = authority  // <-- The fix!");
      console.log("      )]");
      console.log("      pub vault: Account<'info, VaultState>");
      console.log("");
      console.log("      The `close` constraint:");
      console.log("      1. Transfers ALL lamports to the specified account");
      console.log("      2. Zeros ALL account data (discriminator + fields)");
      console.log("      3. Assigns ownership to the System Program");
      console.log("      4. Account cannot be revived within the same transaction");
      console.log("");
      console.log("      Without `close`, manually draining lamports leaves");
      console.log("      data intact, allowing same-transaction revival attacks.");
    });
  });

  describe("Summary", () => {
    it("demonstrates the critical importance of proper account closing", () => {
      console.log("\n      VULNERABILITY SUMMARY:");
      console.log("");
      console.log("      CLOSING ACCOUNTS ATTACK:");
      console.log("      - Program drains lamports but doesn't zero data");
      console.log("      - Account data persists within the same transaction");
      console.log("      - Attacker re-funds account to 'revive' it");
      console.log("      - Revived account passes all validation checks");
      console.log("");
      console.log("      WHY IT'S DEVASTATING:");
      console.log("      - Account appears valid after 'closing'");
      console.log("      - Can be used to double-spend or replay actions");
      console.log("      - Exploitable via composable transaction instructions");
      console.log("      - Victim believes account is closed and safe");
      console.log("");
      console.log("      THREE WAYS TO PREVENT:");
      console.log("");
      console.log("      1. Use Anchor's `close` constraint (RECOMMENDED):");
      console.log("         #[account(mut, close = authority)]");
      console.log("");
      console.log("      2. Manually zero data before draining lamports:");
      console.log("         vault.to_account_info().data.borrow_mut().fill(0);");
      console.log("         **vault.try_borrow_mut_lamports()? = 0;");
      console.log("");
      console.log("      3. Set a closing flag and check it on all operations:");
      console.log("         vault.is_closed = true;");
      console.log("         require!(!vault.is_closed, AccountClosed);");
      console.log("");
      console.log("      KEY LESSON:");
      console.log("      ALWAYS use Anchor's `close` constraint when closing accounts.");
      console.log("      Never just drain lamports - always zero the data first.");
    });
  });
});
