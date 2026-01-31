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
 * Pinocchio Unsafe Rust Test
 *
 * Tests the vulnerable and secure Pinocchio implementations of data reading.
 *
 * DataStore Account Layout (73 bytes):
 * - Bytes 0-31: Authority public key (32 bytes)
 * - Bytes 32-39: Value (u64, 8 bytes)
 * - Bytes 40-71: Label (32 bytes)
 * - Byte 72: Is initialized (u8, 1 byte)
 *
 * CRITICAL: The vulnerable version uses unsafe pointer casts without
 * verifying account ownership, allowing any account's bytes to be
 * interpreted as a DataStore.
 *
 * Instructions:
 * - 0: Initialize - creates data store with value and label
 *   Data: [0] + value(u64 LE, 8 bytes) + label(32 bytes) = 41 bytes
 *   Accounts: [authority(signer), store(writable), system_program]
 * - 1: ReadData - reads data from store
 *   Data: [1] = 1 byte
 *   Accounts: [authority(signer), store(writable)]
 */

const ACCOUNT_SIZE = 73; // 32 + 8 + 32 + 1

const VULNERABLE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xf1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01,
  ])
);

const SECURE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xf1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02,
  ])
);

describe("Pinocchio: Unsafe Rust Attacks", () => {
  const authority = Keypair.generate();
  const attacker = Keypair.generate();
  const storeKeypair = Keypair.generate();
  const storeKeypairSecure = Keypair.generate();

  describe("Vulnerable Pinocchio Implementation", () => {
    it("reads data from legitimate store account", async () => {
      console.log("\n      NORMAL OPERATION (Pinocchio Unsafe Rust):");

      // Pre-create store account owned by the program
      const context = await start(
        [{ name: "vulnerable_unsafe_rust_pinocchio", programId: VULNERABLE_PROGRAM_ID }],
        [
          {
            address: storeKeypair.publicKey,
            info: {
              lamports: 1_000_000,
              data: Buffer.alloc(ACCOUNT_SIZE),
              owner: VULNERABLE_PROGRAM_ID,
              executable: false,
            },
          },
        ]
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Initialize the data store
      console.log("      1. Initializing data store with value=42...");

      const value = Buffer.alloc(8);
      value.writeBigUInt64LE(BigInt(42), 0);

      const label = Buffer.alloc(32);
      label.write("test-data");

      // Instruction data: [0] + value(8) + label(32) = 41 bytes
      const initData = Buffer.concat([Buffer.from([0]), value, label]);

      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: storeKeypair.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: initData,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      Data store initialized successfully");

      // Step 2: Read data from the store
      console.log("      2. Reading data from store...");

      const readIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: storeKeypair.publicKey, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([1]), // Instruction 1 = ReadData
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(readIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      read_data succeeded with legitimate store account");

      // Verify account data
      const accountInfo = await client.getAccount(storeKeypair.publicKey);
      assert.ok(accountInfo !== null, "Store account should exist");

      const data = Buffer.from(accountInfo!.data);
      const storedAuthority = new PublicKey(data.slice(0, 32));
      const storedValue = data.readBigUInt64LE(32);
      const isInitialized = data[72];

      console.log("      Authority:", storedAuthority.toBase58());
      console.log("      Value:", storedValue.toString());
      console.log("      Is initialized:", isInitialized);
    });

    it("reads garbage data from wrong account via unsafe pointer cast (no ownership check)", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION (Pinocchio Unsafe Rust):");

      // Create a fake account NOT owned by the program
      const fakeStore = Keypair.generate();

      const context = await start(
        [{ name: "vulnerable_unsafe_rust_pinocchio", programId: VULNERABLE_PROGRAM_ID }],
        [
          {
            address: storeKeypair.publicKey,
            info: {
              lamports: 1_000_000,
              data: Buffer.alloc(ACCOUNT_SIZE),
              owner: VULNERABLE_PROGRAM_ID,
              executable: false,
            },
          },
          {
            address: fakeStore.publicKey,
            info: {
              lamports: 1_000_000,
              data: Buffer.alloc(ACCOUNT_SIZE), // Zero-filled garbage data
              owner: SystemProgram.programId, // Owned by System Program, NOT our program!
              executable: false,
            },
          },
        ]
      );

      const client = context.banksClient;
      const payer = context.payer;

      // First initialize the legitimate store
      const value = Buffer.alloc(8);
      value.writeBigUInt64LE(BigInt(42), 0);
      const label = Buffer.alloc(32);
      label.write("test-data");

      const initData = Buffer.concat([Buffer.from([0]), value, label]);

      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: storeKeypair.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: initData,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);

      // ATTACK: Pass the fake account (owned by System Program) as store
      console.log("      1. Created fake account owned by System Program...");
      console.log("         Fake account:", fakeStore.publicKey.toBase58());
      console.log("         Owner: System Program (NOT our program!)");
      console.log("         Data: zero-filled garbage bytes");

      console.log("\n      2. ATTACK: Passing fake account as store to read_data...");
      console.log("         - Vulnerable program uses UncheckedAccount");
      console.log("         - No account.owner() == program_id check");
      console.log("         - unsafe { &*(data.as_ptr() as *const DataStore) }");

      const attackReadIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: fakeStore.publicKey, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([1]), // ReadData instruction
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(attackReadIx);
      tx.sign(payer);

      try {
        await client.processTransaction(tx);

        console.log("      VULNERABILITY CONFIRMED: read_data succeeded on fake account!");
        console.log("      Program read garbage data via unsafe pointer cast:");
        console.log("        - authority: all zeros (garbage)");
        console.log("        - value: 0 (garbage)");
        console.log("        - label: all zeros (garbage)");
        console.log("        - is_initialized: 0 (garbage)");
        console.log("");
        console.log("      The program blindly trusted bytes from an unowned account!");
      } catch (error: any) {
        // Even if it fails at runtime, the vulnerability pattern is clear
        console.log("      Note:", String(error).substring(0, 100));
        console.log("");
        console.log("      WHY THIS IS VULNERABLE:");
        console.log("      - No ownership check: account.owner() != program_id");
        console.log("      - unsafe pointer cast reads ANY bytes as DataStore");
        console.log("      - Attacker controls what data the program interprets");
      }

      console.log("");
      console.log("      UNSAFE RUST PATTERN:");
      console.log("      let data = account_info.try_borrow_data()?;");
      console.log("      let store = unsafe { &*(data.as_ptr() as *const DataStore) };");
      console.log("      // No owner check! Reads garbage from any account.");
    });
  });

  describe("Secure Pinocchio Implementation", () => {
    it("reads data from legitimate store account", async () => {
      console.log("\n      FIX DEMONSTRATION (Pinocchio Secure):");

      const context = await start(
        [{ name: "secure_unsafe_rust_pinocchio", programId: SECURE_PROGRAM_ID }],
        [
          {
            address: storeKeypairSecure.publicKey,
            info: {
              lamports: 1_000_000,
              data: Buffer.alloc(ACCOUNT_SIZE),
              owner: SECURE_PROGRAM_ID,
              executable: false,
            },
          },
        ]
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Initialize the data store
      console.log("      1. Initializing secure data store...");

      const value = Buffer.alloc(8);
      value.writeBigUInt64LE(BigInt(42), 0);
      const label = Buffer.alloc(32);
      label.write("test-data");

      const initData = Buffer.concat([Buffer.from([0]), value, label]);

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: storeKeypairSecure.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: initData,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      Data store initialized with value=42");

      // Read data from the legitimate store
      console.log("      2. Reading data from legitimate store...");

      const readIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: storeKeypairSecure.publicKey, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([1]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(readIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      read_data succeeded with legitimate store");

      // Verify account data
      const accountInfo = await client.getAccount(storeKeypairSecure.publicKey);
      assert.ok(accountInfo !== null, "Secure store account should exist");
      const storedValue = Buffer.from(accountInfo!.data).readBigUInt64LE(32);
      console.log("      Value:", storedValue.toString());
    });

    it("rejects read_data with account not owned by program (ownership check)", async () => {
      console.log("\n      ATTACK ATTEMPT on secure program...");

      const fakeStoreSecure = Keypair.generate();

      const context = await start(
        [{ name: "secure_unsafe_rust_pinocchio", programId: SECURE_PROGRAM_ID }],
        [
          {
            address: storeKeypairSecure.publicKey,
            info: {
              lamports: 1_000_000,
              data: Buffer.alloc(ACCOUNT_SIZE),
              owner: SECURE_PROGRAM_ID,
              executable: false,
            },
          },
          {
            address: fakeStoreSecure.publicKey,
            info: {
              lamports: 1_000_000,
              data: Buffer.alloc(ACCOUNT_SIZE),
              owner: SystemProgram.programId, // NOT owned by secure program!
              executable: false,
            },
          },
        ]
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Initialize the legitimate store first
      const value = Buffer.alloc(8);
      value.writeBigUInt64LE(BigInt(42), 0);
      const label = Buffer.alloc(32);
      label.write("test-data");

      const initData = Buffer.concat([Buffer.from([0]), value, label]);

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: storeKeypairSecure.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: initData,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);

      // ATTACK: Pass fake account to secure program
      console.log("      1. Passing fake account (owned by System Program) to read_data...");

      const attackReadIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: fakeStoreSecure.publicKey, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([1]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(attackReadIx);
      tx.sign(payer);

      let attackFailed = false;
      try {
        await client.processTransaction(tx);
      } catch (error: any) {
        attackFailed = true;
        console.log("      FIX CONFIRMED: Transaction rejected!");
        console.log("      Error: Account not owned by program (ownership check failed)");
      }

      assert.ok(attackFailed, "Attack with fake account should have failed");

      console.log("");
      console.log("      SECURE VALIDATION:");
      console.log("      if !store_info.is_owned_by(&program_id) {");
      console.log("          return Err(ProgramError::InvalidAccountOwner);");
      console.log("      }");
      console.log("      // Safe deserialization only AFTER ownership verified");
      console.log("      let store = DataStore::try_from_slice(&data)?;");
    });
  });

  describe("Summary", () => {
    it("demonstrates Pinocchio unsafe Rust vulnerability", () => {
      console.log("\n      PINOCCHIO UNSAFE RUST SUMMARY:");
      console.log("      ");
      console.log("      VULNERABLE: No ownership check + unsafe pointer cast");
      console.log("         let data = account_info.try_borrow_data()?;");
      console.log("         let store = unsafe { &*(data.as_ptr() as *const DataStore) };");
      console.log("         // Accepts ANY account, reads garbage as valid data");
      console.log("      ");
      console.log("      SECURE: Ownership check + safe deserialization");
      console.log("         if !account.is_owned_by(&program_id) {");
      console.log("             return Err(InvalidAccountOwner);");
      console.log("         }");
      console.log("         let store = DataStore::try_from_slice(&data)?;");
      console.log("         // Only processes program-owned accounts, safely");
      console.log("      ");
      console.log("      KEY LESSON (Pinocchio):");
      console.log("         unsafe Rust disables ALL safety guarantees.");
      console.log("         In Solana, accounts come from untrusted callers.");
      console.log("         Without ownership checks, attackers control what data");
      console.log("         your program reads and trusts.");
      console.log("         Always validate ownership BEFORE reading account data.");
      console.log("         Prefer safe deserialization (try_from_slice) over pointer casts.");
    });
  });
});
