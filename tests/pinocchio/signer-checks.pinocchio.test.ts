import { start } from "solana-bankrun";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import * as path from "path";
import { assert } from "chai";

/**
 * Pinocchio Signer Checks Test
 *
 * Tests the vulnerable and secure Pinocchio implementations of signer checks.
 *
 * Account Layout (41 bytes):
 * - Byte 0: Initialized flag (1 = initialized)
 * - Bytes 1-32: Owner public key (32 bytes)
 * - Bytes 33-40: Data field (8 bytes, u64)
 *
 * Instructions:
 * - 0: Initialize - creates account with owner
 * - 1: UpdateOwner - changes owner (vulnerable version doesn't check signer!)
 */

// Program IDs (must match the constants in the Pinocchio lib.rs files)
const VULNERABLE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xd1, 0x6c, 0x7e, 0x1f, 0x8a, 0xb3, 0x4c, 0x5d,
    0xe9, 0x2a, 0x1b, 0xf6, 0xc3, 0x7d, 0x4e, 0x8f,
    0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0b, 0x1c,
    0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x01,
  ])
);

const SECURE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xd1, 0x6c, 0x7e, 0x1f, 0x8a, 0xb3, 0x4c, 0x5d,
    0xe9, 0x2a, 0x1b, 0xf6, 0xc3, 0x7d, 0x4e, 0x8f,
    0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xfa, 0x0b, 0x1c,
    0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x02,
  ])
);

const ACCOUNT_SIZE = 41; // 1 + 32 + 8 bytes

describe("Pinocchio: Missing Signer Checks", () => {
  // Test keypairs
  const alice = Keypair.generate();
  const attacker = Keypair.generate();
  const programAccount = Keypair.generate();
  const programAccountSecure = Keypair.generate();

  describe("Vulnerable Pinocchio Implementation", () => {
    it("allows attacker to steal ownership WITHOUT victim's signature", async () => {
      console.log("\n      🔥 EXPLOIT DEMONSTRATION (Pinocchio Vulnerable):");

      // Start bankrun with the vulnerable program
      const context = await start(
        [
          {
            name: "vulnerable_signer_checks_pinocchio",
            programId: VULNERABLE_PROGRAM_ID,
          },
        ],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Create and allocate the program account
      console.log("      1. Creating program account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: programAccount.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: VULNERABLE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, programAccount);

      await client.processTransaction(tx);
      console.log("      ✅ Program account created");

      // Step 2: Alice initializes her account
      console.log("      2. Alice initializes her account...");
      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: alice.publicKey, isSigner: true, isWritable: false },
          { pubkey: programAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([0]), // Instruction 0 = Initialize
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer, alice);

      await client.processTransaction(tx);
      console.log("      ✅ Alice's account initialized");

      // Verify Alice is owner
      let accountInfo = await client.getAccount(programAccount.publicKey);
      let ownerKey = new PublicKey(accountInfo!.data.slice(1, 33));
      assert.ok(ownerKey.equals(alice.publicKey), "Alice should be initial owner");
      console.log("      ✅ Verified: Owner is Alice");

      // Step 3: ATTACK - Attacker steals ownership without Alice's signature!
      console.log("\n      3. 🚨 ATTACK: Attacker calls update_owner...");
      console.log("         - Passes Alice's pubkey (but Alice does NOT sign!)");
      console.log("         - Passes Attacker's pubkey as new owner");

      const attackIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: alice.publicKey, isSigner: false, isWritable: false }, // NOT a signer!
          { pubkey: programAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: attacker.publicKey, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([1]), // Instruction 1 = UpdateOwner
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(attackIx);
      tx.sign(payer); // Only payer signs - Alice does NOT sign!

      await client.processTransaction(tx);
      console.log("      ⚠️  VULNERABILITY CONFIRMED: Transaction succeeded!");

      // Verify attacker is now owner
      accountInfo = await client.getAccount(programAccount.publicKey);
      ownerKey = new PublicKey(accountInfo!.data.slice(1, 33));

      assert.ok(ownerKey.equals(attacker.publicKey), "Attacker should now own the account");
      console.log("      💀 Account stolen! New owner:", ownerKey.toBase58());
      console.log("      💀 Original owner (Alice):", alice.publicKey.toBase58());
    });
  });

  describe("Secure Pinocchio Implementation", () => {
    it("prevents attacker from stealing ownership - requires victim's signature", async () => {
      console.log("\n      🛡️  FIX DEMONSTRATION (Pinocchio Secure):");

      // Start bankrun with the secure program
      const context = await start(
        [
          {
            name: "secure_signer_checks_pinocchio",
            programId: SECURE_PROGRAM_ID,
          },
        ],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Create and allocate the program account
      console.log("      1. Creating program account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: programAccountSecure.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: SECURE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, programAccountSecure);

      await client.processTransaction(tx);

      // Step 2: Alice initializes her account
      console.log("      2. Alice initializes her account (secure version)...");
      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: alice.publicKey, isSigner: true, isWritable: false },
          { pubkey: programAccountSecure.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([0]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer, alice);

      await client.processTransaction(tx);
      console.log("      ✅ Alice's account initialized");

      // Verify Alice is owner
      let accountInfo = await client.getAccount(programAccountSecure.publicKey);
      let ownerKey = new PublicKey(accountInfo!.data.slice(1, 33));
      assert.ok(ownerKey.equals(alice.publicKey), "Alice should be initial owner");

      // Step 3: ATTACK ATTEMPT - Should fail!
      console.log("\n      3. 🔥 ATTACK ATTEMPT on secure program...");
      console.log("         - Attacker tries to pass Alice's pubkey without signature");

      const attackIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: alice.publicKey, isSigner: false, isWritable: false }, // NOT a signer
          { pubkey: programAccountSecure.publicKey, isSigner: false, isWritable: true },
          { pubkey: attacker.publicKey, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([1]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(attackIx);
      tx.sign(payer);

      let attackFailed = false;
      try {
        await client.processTransaction(tx);
      } catch (error: any) {
        attackFailed = true;
        console.log("      ✅ FIX CONFIRMED: Transaction rejected!");
        console.log("      📋 Error: Missing required signature (is_signer check failed)");
      }

      assert.ok(attackFailed, "Attack should have failed");

      // Verify Alice still owns the account
      accountInfo = await client.getAccount(programAccountSecure.publicKey);
      ownerKey = new PublicKey(accountInfo!.data.slice(1, 33));

      assert.ok(ownerKey.equals(alice.publicKey), "Alice should still own the account");
      console.log("      🛡️  Alice's account is secure! Owner:", ownerKey.toBase58());
    });
  });

  describe("Summary", () => {
    it("demonstrates Pinocchio signer check vulnerability", () => {
      console.log("\n      📊 PINOCCHIO SIGNER CHECK SUMMARY:");
      console.log("      ");
      console.log("      🔴 VULNERABLE: No is_signer() check in update_owner");
      console.log("         → Accepts any pubkey without verifying signature");
      console.log("         → Attacker passes victim's key, takes ownership");
      console.log("      ");
      console.log("      🟢 SECURE: Explicit is_signer() validation");
      console.log("         → if !owner_info.is_signer() { return Err(...) }");
      console.log("         → Transaction fails without owner's signature");
      console.log("      ");
      console.log("      💡 KEY LESSON (Pinocchio):");
      console.log("         Always call is_signer() for privileged operations!");
      console.log("         Unlike Anchor's Signer<'info>, Pinocchio requires manual checks.");
    });
  });
});
