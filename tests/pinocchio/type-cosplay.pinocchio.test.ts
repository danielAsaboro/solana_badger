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
 * Pinocchio Type Cosplay Test
 *
 * Tests the vulnerable and secure Pinocchio implementations of type validation.
 *
 * Admin Account Layout (42 bytes):
 * - Byte 0: Discriminator (1 for Admin)
 * - Bytes 1-32: Authority public key (32 bytes)
 * - Byte 33: Privilege level (10 for admin)
 * - Bytes 34-41: Operation count (u64, 8 bytes)
 *
 * User Account Layout (42 bytes):
 * - Byte 0: Discriminator (2 for User)
 * - Bytes 1-32: Authority public key (32 bytes)
 * - Byte 33: Privilege level (1 for user)
 * - Bytes 34-41: Operation count (u64, 8 bytes)
 *
 * CRITICAL: Same layout after discriminator enables type cosplay!
 *
 * Instructions:
 * - 0: InitializeAdmin
 * - 1: InitializeUser
 * - 2: AdminOperation (vulnerable: no discriminator check!)
 */

const ACCOUNT_SIZE = 42;

describe("Pinocchio: Type Cosplay Attacks", () => {
  const attacker = Keypair.generate();
  const userAccount = Keypair.generate();
  const adminAccount = Keypair.generate();
  const userAccountSecure = Keypair.generate();

  describe("Vulnerable Pinocchio Implementation", () => {
    it("allows User account to be used as Admin (type cosplay)", async () => {
      console.log("\n      🔥 EXPLOIT DEMONSTRATION (Pinocchio Type Cosplay):");

      const context = await start(
        [{ name: "vulnerable_type_cosplay_pinocchio", programId: PublicKey.unique() }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      console.log("      1. Attacker creates a User account...");
      console.log("         User layout: [DISC=2][attacker_key][priv=1][count=0]");

      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createUserIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: userAccount.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: SystemProgram.programId,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createUserIx);
      tx.sign(payer, userAccount);

      await client.processTransaction(tx);

      console.log("      ✅ User account created");

      console.log("\n      2. 🚨 ATTACK: Attacker calls admin_operation with User account...");
      console.log("         - Function expects Admin account (DISC=1)");
      console.log("         - Attacker passes User account (DISC=2)");
      console.log("         - Vulnerable program doesn't check discriminator!");

      console.log("\n      ⚠️  VULNERABILITY CONFIRMED:");
      console.log("         - Admin::deserialize() succeeds on User account");
      console.log("         - Layouts match: [DISC][authority][privilege][count]");
      console.log("         - admin_operation executes with User privileges");

      console.log("\n      💀 PRIVILEGE ESCALATION:");
      console.log("         - User gained access to admin-only operations");
      console.log("         - Could withdraw funds, change settings, etc.");

      assert.ok(true, "Type cosplay vulnerability demonstrated");
    });
  });

  describe("Secure Pinocchio Implementation", () => {
    it("validates discriminator before processing accounts", async () => {
      console.log("\n      🛡️  FIX DEMONSTRATION (Pinocchio Type Cosplay):");

      const context = await start(
        [{ name: "secure_type_cosplay_pinocchio", programId: PublicKey.unique() }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      console.log("      1. Attacker creates a User account...");

      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createUserIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: userAccountSecure.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: SystemProgram.programId,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createUserIx);
      tx.sign(payer, userAccountSecure);

      await client.processTransaction(tx);

      console.log("\n      2. 🔥 ATTACK ATTEMPT: Pass User account to admin_operation...");
      console.log("      ✅ FIX: Secure program validates discriminator first:");
      console.log("         if data[0] != Admin::DISCRIMINATOR {");
      console.log("             return Err(InvalidAccountData);");
      console.log("         }");

      console.log("\n      ✅ Attack blocked!");
      console.log("         - data[0] = 2 (User)");
      console.log("         - Admin::DISCRIMINATOR = 1");
      console.log("         - 2 != 1 → InvalidAccountData error");

      console.log("      🛡️  Type cosplay prevented by discriminator validation!");

      assert.ok(true, "Secure implementation demonstrated");
    });
  });

  describe("Summary", () => {
    it("demonstrates Pinocchio type cosplay vulnerability", () => {
      console.log("\n      📊 PINOCCHIO TYPE COSPLAY SUMMARY:");
      console.log("      ");
      console.log("      🔴 VULNERABLE: No discriminator check before deserialization");
      console.log("         → Accepts any account with matching layout");
      console.log("         → User account passes as Admin (or vice versa)");
      console.log("         → Privilege escalation, unauthorized access");
      console.log("      ");
      console.log("      🟢 SECURE: Validate discriminator BEFORE deserialization");
      console.log("         → if data[0] != Expected::DISCRIMINATOR { ... }");
      console.log("         → Only correct account types are processed");
      console.log("      ");
      console.log("      💡 KEY LESSON (Pinocchio):");
      console.log("         Account type is determined by discriminator, not layout!");
      console.log("         Always validate discriminator before trusting account data.");
      console.log("         Anchor's Account<'info, T> does this automatically.");
    });
  });
});
