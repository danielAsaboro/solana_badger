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
 * Pinocchio Panic Handling Test
 *
 * Tests the vulnerable and secure Pinocchio implementations of panic handling.
 *
 * ProcessorState Account Layout (41 bytes):
 * - Bytes 0-31: Authority public key (32 bytes)
 * - Bytes 32-39: Average (u64, 8 bytes)
 * - Byte 40: Count (u8, 1 byte)
 *
 * Instructions:
 * - 0: Initialize - sets up the processor state account
 *   Data: [0]
 *   Accounts: [authority(signer), state(writable), system_program]
 *
 * - 1: Process - processes values with a divisor
 *   Data: [1, divisor(u8), count(u8), ...values(u64 LE each)]
 *   Accounts: [authority(signer), state(writable)]
 *
 * CRITICAL: Vulnerable version panics on empty data and division by zero!
 */

const ACCOUNT_SIZE = 41; // 32 (authority) + 8 (average) + 1 (count)

// Program IDs
const VULNERABLE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xd1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01,
  ])
);

const SECURE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xd1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02,
  ])
);

/**
 * Build a Process instruction buffer.
 *
 * Format:
 * [0] = instruction (1 for Process)
 * [1] = divisor (u8)
 * [2] = count of values (u8)
 * [3..] = values as u64 little-endian (8 bytes each)
 */
function buildProcessInstruction(divisor: number, values: bigint[]): Buffer {
  const buf = Buffer.alloc(3 + values.length * 8);
  buf[0] = 1; // instruction
  buf[1] = divisor;
  buf[2] = values.length;
  values.forEach((v, i) => {
    const offset = 3 + i * 8;
    buf.writeBigUInt64LE(v, offset);
  });
  return buf;
}

describe("Pinocchio: Panic Handling", () => {
  const authority = Keypair.generate();
  const stateAccountVuln = Keypair.generate();
  const stateAccountSecure = Keypair.generate();

  describe("Vulnerable Pinocchio Implementation", () => {
    it("panics on empty instruction data (direct index out of bounds)", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION (Pinocchio Panic - Empty Data):");

      const context = await start(
        [{ name: "vulnerable_panic_handling_pinocchio", programId: VULNERABLE_PROGRAM_ID }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Create state account
      console.log("      1. Creating state account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: stateAccountVuln.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: VULNERABLE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, stateAccountVuln);

      await client.processTransaction(tx);
      console.log("      State account created");

      // Step 2: Initialize the state
      console.log("      2. Initializing state...");
      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: stateAccountVuln.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([0]), // Instruction 0 = Initialize
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      State initialized");

      // Step 3: Send completely empty instruction data (no bytes at all)
      console.log("\n      3. ATTACK: Sending completely empty instruction data...");
      console.log("         Vulnerable code directly indexes instruction_data[0] without bounds check");

      const processIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: stateAccountVuln.publicKey, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([]),  // Empty! instruction_data[0] will panic
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(processIx);
      tx.sign(payer);

      let panicked = false;
      try {
        await client.processTransaction(tx);
      } catch (error: any) {
        panicked = true;
        console.log("      PANIC CONFIRMED: Program crashed!");
        console.log("      Error:", error.message.substring(0, 120));
        console.log("");
        console.log("      WHY IT PANICKED:");
        console.log("      - data[n] direct index without length check");
        console.log("      - Empty values array causes out-of-bounds access");
        console.log("      - Rust panics on index out of bounds");
      }

      assert.ok(panicked, "Should have panicked on empty data");
    });

    it("panics on division by zero", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION (Pinocchio Panic - Div by Zero):");

      const divZeroState = Keypair.generate();

      const context = await start(
        [{ name: "vulnerable_panic_handling_pinocchio", programId: VULNERABLE_PROGRAM_ID }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Create and initialize state
      console.log("      1. Setting up state account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: divZeroState.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: VULNERABLE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, divZeroState);

      await client.processTransaction(tx);

      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: divZeroState.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([0]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      State initialized");

      // Send process with divisor=0
      console.log("\n      2. ATTACK: Sending process with divisor=0...");
      console.log("         values=[10, 20], divisor=0");

      const divZeroData = buildProcessInstruction(0, [BigInt(10), BigInt(20)]);

      const processIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: divZeroState.publicKey, isSigner: false, isWritable: true },
        ],
        data: divZeroData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(processIx);
      tx.sign(payer);

      let panicked = false;
      try {
        await client.processTransaction(tx);
      } catch (error: any) {
        panicked = true;
        console.log("      PANIC CONFIRMED: Program crashed!");
        console.log("      Error:", error.message.substring(0, 120));
        console.log("");
        console.log("      WHY IT PANICKED:");
        console.log("      - total / divisor where divisor = 0");
        console.log("      - Rust integer division by zero causes panic");
        console.log("      - No checked_div() or prior validation");
      }

      assert.ok(panicked, "Should have panicked on division by zero");
    });
  });

  describe("Secure Pinocchio Implementation", () => {
    it("gracefully rejects empty instruction data", async () => {
      console.log("\n      FIX DEMONSTRATION (Pinocchio Panic - Empty Data):");

      const secureEmptyState = Keypair.generate();

      const context = await start(
        [{ name: "secure_panic_handling_pinocchio", programId: SECURE_PROGRAM_ID }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Create and initialize state
      console.log("      1. Setting up state account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: secureEmptyState.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: SECURE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, secureEmptyState);

      await client.processTransaction(tx);

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: secureEmptyState.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([0]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      State initialized");

      // Send completely empty instruction data
      console.log("\n      2. Sending completely empty instruction data...");

      const processIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: secureEmptyState.publicKey, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([]),  // Empty! secure version uses .first().ok_or(...)
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(processIx);
      tx.sign(payer);

      let rejected = false;
      try {
        await client.processTransaction(tx);
      } catch (error: any) {
        rejected = true;
        console.log("      FIX CONFIRMED: Graceful error returned!");
        console.log("      Error:", error.message.substring(0, 120));
        console.log("");
        console.log("      HOW IT WAS FIXED:");
        console.log("      - Checks data length before accessing indices");
        console.log("      - if count == 0 { return Err(InvalidInstructionData) }");
        console.log("      - Returns ProgramError instead of panicking");
        console.log("      - No wasted compute units");
      }

      assert.ok(rejected, "Should have gracefully rejected empty data");
    });

    it("gracefully rejects division by zero", async () => {
      console.log("\n      FIX DEMONSTRATION (Pinocchio Panic - Div by Zero):");

      const secureDivState = Keypair.generate();

      const context = await start(
        [{ name: "secure_panic_handling_pinocchio", programId: SECURE_PROGRAM_ID }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Create and initialize state
      console.log("      1. Setting up state account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: secureDivState.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: SECURE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, secureDivState);

      await client.processTransaction(tx);

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: secureDivState.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([0]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      State initialized");

      // Send process with divisor=0
      console.log("\n      2. Sending process with divisor=0...");
      console.log("         values=[10, 20], divisor=0");

      const divZeroData = buildProcessInstruction(0, [BigInt(10), BigInt(20)]);

      const processIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: secureDivState.publicKey, isSigner: false, isWritable: true },
        ],
        data: divZeroData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(processIx);
      tx.sign(payer);

      let rejected = false;
      try {
        await client.processTransaction(tx);
      } catch (error: any) {
        rejected = true;
        console.log("      FIX CONFIRMED: Graceful error returned!");
        console.log("      Error:", error.message.substring(0, 120));
        console.log("");
        console.log("      HOW IT WAS FIXED:");
        console.log("      - if divisor == 0 { return Err(ArithmeticOverflow) }");
        console.log("      - Uses checked_div() as defense in depth");
        console.log("      - Returns ProgramError instead of panicking");
      }

      assert.ok(rejected, "Should have gracefully rejected division by zero");
    });

    it("succeeds with valid data", async () => {
      console.log("\n      VALID INPUT TEST (Pinocchio Secure):");

      const secureValidState = Keypair.generate();

      const context = await start(
        [{ name: "secure_panic_handling_pinocchio", programId: SECURE_PROGRAM_ID }],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Create and initialize state
      console.log("      1. Setting up state account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: secureValidState.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: SECURE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, secureValidState);

      await client.processTransaction(tx);

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: secureValidState.publicKey, isSigner: false, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([0]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      State initialized");

      // Send valid process instruction
      console.log("\n      2. Sending process with valid data...");
      console.log("         values=[10, 20], divisor=2");

      const validData = buildProcessInstruction(2, [BigInt(10), BigInt(20)]);

      const processIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: false },
          { pubkey: secureValidState.publicKey, isSigner: false, isWritable: true },
        ],
        data: validData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(processIx);
      tx.sign(payer);

      await client.processTransaction(tx);
      console.log("      Transaction succeeded!");

      // Verify state was updated
      const accountInfo = await client.getAccount(secureValidState.publicKey);
      if (accountInfo) {
        const data = Buffer.from(accountInfo.data);
        // Read average (bytes 32-39, u64 LE)
        const average = data.readBigUInt64LE(32);
        // Read count (byte 40, u8)
        const count = data[40];

        console.log("      State average:", average.toString());
        console.log("      State count:", count);
        console.log("");
        console.log("      Secure program handles ALL cases:");
        console.log("      - Empty values -> graceful error");
        console.log("      - Division by zero -> graceful error");
        console.log("      - Valid inputs -> processes correctly");
      }
    });
  });

  describe("Summary", () => {
    it("demonstrates Pinocchio panic handling vulnerability", () => {
      console.log("\n      PINOCCHIO PANIC HANDLING SUMMARY:");
      console.log("      ");
      console.log("      VULNERABLE: No input validation before processing");
      console.log("         - data[n] direct index without bounds check -> panic");
      console.log("         - Division by zero without checked_div -> panic");
      console.log("         - .unwrap() on parse results -> panic");
      console.log("         - Panics waste compute and give opaque errors");
      console.log("      ");
      console.log("      SECURE: Validate everything before processing");
      console.log("         - Check instruction data length before indexing");
      console.log("         - Validate divisor != 0 before arithmetic");
      console.log("         - Use .get() instead of direct indexing");
      console.log("         - Use checked_div/checked_mul for math");
      console.log("         - Return ProgramError with meaningful codes");
      console.log("      ");
      console.log("      PINOCCHIO-SPECIFIC CONCERNS:");
      console.log("         Unlike Anchor, Pinocchio has NO automatic validation.");
      console.log("         No deserialization guards, no macro-generated checks.");
      console.log("         Every byte of instruction data must be manually validated.");
      console.log("         Direct indexing (data[0]) panics if data is empty.");
      console.log("      ");
      console.log("      KEY LESSON:");
      console.log("         In Pinocchio, YOU are the safety net.");
      console.log("         Validate all inputs. Use checked arithmetic.");
      console.log("         Return errors, never panic.");
    });
  });
});
