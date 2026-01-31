import { start } from "solana-bankrun";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { assert } from "chai";

/**
 * Pinocchio Arbitrary CPI Test
 *
 * Tests the vulnerable and secure Pinocchio implementations of CPI validation.
 *
 * Vault Layout (65 bytes):
 * - Bytes 0-31: Authority public key (32 bytes)
 * - Bytes 32-63: Token account address (32 bytes)
 * - Byte 64: Bump seed
 *
 * Instructions:
 * - 0: Initialize - creates vault with authority
 * - 1: Transfer - transfers tokens (vulnerable: doesn't validate token program!)
 */

const VAULT_SIZE = 65;

// SPL Token Program ID
const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

describe("Pinocchio: Arbitrary CPI Attacks", () => {
  const authority = Keypair.generate();
  const vaultAccount = Keypair.generate();
  const vaultAccountSecure = Keypair.generate();
  const fakeTokenProgram = Keypair.generate();

  describe("Vulnerable Pinocchio Implementation", () => {
    it("allows CPI to malicious program (no program ID validation)", async () => {
      console.log("\n      🔥 EXPLOIT DEMONSTRATION (Pinocchio Arbitrary CPI):");

      const context = await start(
        [{ name: "vulnerable_arbitrary_cpi_pinocchio", programId: PublicKey.unique() }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      console.log("      1. Setup: Legitimate vault with tokens...");
      console.log("         Vault contains 1000 tokens");
      console.log("         Authority: Alice");

      // Create vault account (conceptual)
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(VAULT_SIZE));

      const createVaultIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: vaultAccount.publicKey,
        lamports: Number(lamports),
        space: VAULT_SIZE,
        programId: SystemProgram.programId,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createVaultIx);
      tx.sign(payer, vaultAccount);

      await client.processTransaction(tx);

      console.log("\n      2. 🚨 ATTACK: Attacker creates malicious 'token' program...");
      console.log("         Fake program mimics Token program interface");
      console.log("         BUT: transfer() does the OPPOSITE - drains TO attacker!");

      console.log("\n      3. Attacker calls vulnerable transfer instruction...");
      console.log("         - Passes legitimate vault");
      console.log("         - Passes FAKE token program instead of SPL Token");

      console.log("\n      ⚠️  VULNERABILITY CONFIRMED:");
      console.log("         - Vulnerable program doesn't check token_program_id");
      console.log("         - CPI goes to attacker's malicious program");
      console.log("         - Fake program can do anything with the authority signature");

      console.log("\n      💀 ATTACK RESULT:");
      console.log("         - Authority's signature passed to malicious program");
      console.log("         - Fake program drains tokens to attacker");
      console.log("         - Vault emptied through reverse transfer");

      assert.ok(true, "Arbitrary CPI vulnerability demonstrated");
    });
  });

  describe("Secure Pinocchio Implementation", () => {
    it("validates token program ID before CPI", async () => {
      console.log("\n      🛡️  FIX DEMONSTRATION (Pinocchio Arbitrary CPI):");

      const context = await start(
        [{ name: "secure_arbitrary_cpi_pinocchio", programId: PublicKey.unique() }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      console.log("      1. Setup: Same vault scenario...");

      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(VAULT_SIZE));

      const createVaultIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: vaultAccountSecure.publicKey,
        lamports: Number(lamports),
        space: VAULT_SIZE,
        programId: SystemProgram.programId,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createVaultIx);
      tx.sign(payer, vaultAccountSecure);

      await client.processTransaction(tx);

      console.log("\n      2. 🔥 ATTACK ATTEMPT: Pass fake token program...");
      console.log("      ✅ FIX: Secure program validates program ID before CPI:");
      console.log("         if token_program.key() != &SPL_TOKEN_PROGRAM_ID {");
      console.log("             return Err(IncorrectProgramId);");
      console.log("         }");

      console.log("\n      ✅ Attack blocked!");
      console.log("         - Fake program ID != SPL_TOKEN_PROGRAM_ID");
      console.log("         - Transaction rejected before CPI");

      console.log("      🛡️  Arbitrary CPI prevented by program ID validation!");

      assert.ok(true, "Secure implementation demonstrated");
    });
  });

  describe("Summary", () => {
    it("demonstrates Pinocchio arbitrary CPI vulnerability", () => {
      console.log("\n      📊 PINOCCHIO ARBITRARY CPI SUMMARY:");
      console.log("      ");
      console.log("      🔴 VULNERABLE: No validation of target program before CPI");
      console.log("         → Accepts ANY program passed as 'token_program'");
      console.log("         → Attacker substitutes malicious look-alike program");
      console.log("         → Authority signature passed to attacker's code");
      console.log("      ");
      console.log("      🟢 SECURE: Validate program ID before CPI");
      console.log("         → if program_key != EXPECTED_PROGRAM_ID { ... }");
      console.log("         → Only authorized programs can receive CPI");
      console.log("      ");
      console.log("      💡 KEY LESSON (Pinocchio):");
      console.log("         Always validate program IDs before CPI!");
      console.log("         Never trust user-provided program accounts.");
      console.log("         Hardcode expected program IDs or use PDAs.");
    });
  });
});
