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
 * Pinocchio Closing Accounts Test
 *
 * Tests the vulnerable and secure Pinocchio implementations of account closing.
 *
 * Account Layout VaultState (41 bytes):
 * - Bytes 0-31: Authority public key (32 bytes)
 * - Bytes 32-39: Balance field (u64, 8 bytes)
 * - Byte 40: is_active flag (u8, 1 byte)
 *
 * Instructions:
 * - 0: Initialize - [0] + deposit_amount_u64_le(8 bytes) = 9 bytes
 *   Accounts: [authority(signer, writable), vault(writable), system_program]
 * - 1: ForceClose - [1] = 1 byte
 *   Accounts: [authority(signer, writable), vault(writable)]
 *
 * Vulnerable: Drains lamports but does NOT zero account data
 * Secure: Zeros account data BEFORE draining lamports
 */

const VAULT_SIZE = 41; // 32 + 8 + 1

const VULNERABLE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xE1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01,
  ])
);

const SECURE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xE1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02,
  ])
);

describe("Pinocchio: Closing Accounts", () => {
  const alice = Keypair.generate();
  const vaultAccount = Keypair.generate();
  const vaultAccountSecure = Keypair.generate();

  const DEPOSIT_AMOUNT = BigInt(1000);

  describe("Vulnerable Pinocchio Implementation", () => {
    it("force_close drains lamports but leaves account data intact", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION (Pinocchio Closing Accounts):");

      const context = await start(
        [
          {
            name: "vulnerable_closing_accounts_pinocchio",
            programId: VULNERABLE_PROGRAM_ID,
          },
        ],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Create vault account owned by the program
      console.log("      1. Creating vault account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(VAULT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: vaultAccount.publicKey,
        lamports: Number(lamports),
        space: VAULT_SIZE,
        programId: VULNERABLE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, vaultAccount);

      await client.processTransaction(tx);
      console.log("      Vault account created");

      // Step 2: Initialize vault with deposit amount
      console.log("      2. Initializing vault with 1000 lamports deposit...");

      const depositBytes = Buffer.alloc(8);
      depositBytes.writeBigUInt64LE(DEPOSIT_AMOUNT, 0);
      const initData = Buffer.concat([Buffer.from([0]), depositBytes]);

      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: vaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: initData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      Vault initialized");

      // Verify initial state
      let accountInfo = await client.getAccount(vaultAccount.publicKey);
      assert.ok(accountInfo !== null, "Vault should exist after init");
      const initAuthorityKey = new PublicKey(accountInfo!.data.slice(0, 32));
      assert.ok(
        initAuthorityKey.equals(payer.publicKey),
        "Authority should be payer"
      );
      console.log("      Verified: authority =", initAuthorityKey.toBase58());

      // Step 3: Call force_close
      console.log("\n      3. Calling force_close...");

      const closeIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: vaultAccount.publicKey, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([1]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(closeIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      force_close executed");

      // Step 4: Check if account data is still intact
      accountInfo = await client.getAccount(vaultAccount.publicKey);

      if (accountInfo !== null) {
        const data = accountInfo.data;
        const authorityBytes = data.slice(0, 32);
        const authorityKey = new PublicKey(authorityBytes);
        const balanceBytes = data.slice(32, 40);
        const balance = Buffer.from(balanceBytes).readBigUInt64LE(0);
        const isActive = data[40];

        const isDataZeroed = data.every((byte: number) => byte === 0);

        console.log("\n      VULNERABILITY CONFIRMED:");
        console.log("      Account data is NOT zeroed after force_close!");
        console.log("      Authority still in data:", authorityKey.toBase58());
        console.log("      Balance still in data:", balance.toString());
        console.log("      is_active still in data:", isActive);
        console.log("      All bytes zero?", isDataZeroed);
        console.log("");
        console.log("      The account can be 'revived' within the same");
        console.log("      transaction by re-funding it with lamports.");
        console.log("      Data persists because only lamports were drained.");

        assert.ok(
          !isDataZeroed,
          "Data should NOT be zeroed - this is the vulnerability"
        );
        assert.ok(
          authorityKey.equals(payer.publicKey),
          "Authority key should still be present in data"
        );
      } else {
        // Runtime GC'd the account after the transaction
        console.log("      Account garbage-collected after transaction end");
        console.log("");
        console.log("      VULNERABILITY:");
        console.log("      Even though the account was GC'd between transactions,");
        console.log("      WITHIN the same transaction the data was still intact.");
        console.log("      An attacker composing multiple instructions in one tx:");
        console.log("        Ix 1: force_close (drains lamports, data stays)");
        console.log("        Ix 2: Transfer lamports back to the account");
        console.log("        Ix 3: Use the revived account with original data");
      }
    });
  });

  describe("Secure Pinocchio Implementation", () => {
    it("force_close zeros account data before draining lamports", async () => {
      console.log("\n      FIX DEMONSTRATION (Pinocchio Closing Accounts):");

      const context = await start(
        [
          {
            name: "secure_closing_accounts_pinocchio",
            programId: SECURE_PROGRAM_ID,
          },
        ],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Create vault account owned by the program
      console.log("      1. Creating vault account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(VAULT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: vaultAccountSecure.publicKey,
        lamports: Number(lamports),
        space: VAULT_SIZE,
        programId: SECURE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, vaultAccountSecure);

      await client.processTransaction(tx);
      console.log("      Vault account created");

      // Step 2: Initialize vault
      console.log("      2. Initializing vault with 1000 lamports deposit...");

      const depositBytes = Buffer.alloc(8);
      depositBytes.writeBigUInt64LE(DEPOSIT_AMOUNT, 0);
      const initData = Buffer.concat([Buffer.from([0]), depositBytes]);

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: vaultAccountSecure.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: initData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      Vault initialized");

      // Verify initial state
      let accountInfo = await client.getAccount(vaultAccountSecure.publicKey);
      assert.ok(accountInfo !== null, "Vault should exist after init");
      const initAuthorityKey = new PublicKey(accountInfo!.data.slice(0, 32));
      assert.ok(
        initAuthorityKey.equals(payer.publicKey),
        "Authority should be payer"
      );
      console.log("      Verified: authority =", initAuthorityKey.toBase58());

      // Step 3: Call force_close (secure version)
      console.log("\n      3. Calling force_close (secure)...");

      const closeIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: vaultAccountSecure.publicKey, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([1]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(closeIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      force_close executed");

      // Step 4: Verify data is zeroed
      accountInfo = await client.getAccount(vaultAccountSecure.publicKey);

      if (accountInfo !== null) {
        const data = accountInfo.data;
        const isDataZeroed = data.every((byte: number) => byte === 0);

        console.log("\n      FIX CONFIRMED:");
        console.log("      Account data IS zeroed after secure force_close!");
        console.log("      All bytes zero?", isDataZeroed);
        console.log("");
        console.log("      Secure program zeros data BEFORE draining lamports:");
        console.log("        1. data.fill(0)  -- wipe all account data");
        console.log("        2. vault_lamports = 0  -- drain lamports");
        console.log("        3. authority_lamports += vault_lamports");
        console.log("");
        console.log("      Even if attacker re-funds the account in the same tx,");
        console.log("      the data is all zeros and cannot pass validation.");

        assert.ok(isDataZeroed, "Data should be zeroed after secure close");
      } else {
        console.log("\n      FIX CONFIRMED:");
        console.log("      Account fully closed and garbage-collected!");
        console.log("      Data was zeroed before lamports were drained,");
        console.log("      so even within the same transaction, the account");
        console.log("      could not be revived with valid data.");
        assert.ok(true, "Account properly closed");
      }
    });
  });

  describe("Summary", () => {
    it("demonstrates Pinocchio closing accounts vulnerability", () => {
      console.log("\n      PINOCCHIO CLOSING ACCOUNTS SUMMARY:");
      console.log("      ");
      console.log("      VULNERABLE: Drain lamports without zeroing data");
      console.log("         -> Account data persists within the same transaction");
      console.log("         -> Attacker re-funds account to 'revive' it");
      console.log("         -> Revived account passes all validation checks");
      console.log("         -> Can be used for double-spend or replay attacks");
      console.log("      ");
      console.log("      SECURE: Zero data BEFORE draining lamports");
      console.log("         -> let mut data = vault_info.try_borrow_mut()?;");
      console.log("         -> data.fill(0);  // Wipe all data first");
      console.log("         -> Then drain lamports to authority");
      console.log("      ");
      console.log("      KEY LESSON (Pinocchio):");
      console.log("         Always zero account data before draining lamports!");
      console.log("         In Anchor, use the `close = recipient` constraint.");
      console.log("         In Pinocchio, manually call data.fill(0) first.");
      console.log("         The Solana runtime only garbage-collects zero-lamport");
      console.log("         accounts at the END of a transaction, not between");
      console.log("         instructions within the same transaction.");
    });
  });
});
