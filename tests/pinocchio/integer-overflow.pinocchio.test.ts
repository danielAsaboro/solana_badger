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
 * Pinocchio Integer Overflow Test
 *
 * Tests the vulnerable and secure Pinocchio implementations of integer overflow/underflow.
 *
 * Account Layout (VaultState, 40 bytes):
 * - Bytes 0-31: Owner public key (32 bytes)
 * - Bytes 32-39: Balance field (8 bytes, u64 LE)
 *
 * Instructions:
 * - 0: Initialize - sets owner and balance to 0
 * - 1: Deposit(amount: u64) - adds amount to balance
 * - 2: Withdraw(amount: u64) - subtracts amount from balance
 *
 * Instruction data format: [instruction_byte] + [amount_le_bytes(u64)] = 9 bytes
 * Account keys: [vault_info(writable), owner_info(signer)]
 */

// Program IDs (must match the constants in the Pinocchio lib.rs files)
const VULNERABLE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xC1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01,
  ])
);

const SECURE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xC1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02,
  ])
);

const ACCOUNT_SIZE = 40; // 32 (owner) + 8 (balance)

/**
 * Encode a u64 value as an 8-byte little-endian Buffer.
 */
function encodeU64LE(value: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(value);
  return buf;
}

/**
 * Read the balance (u64 LE) from vault account data at offset 32.
 */
function readBalance(data: Uint8Array): bigint {
  const buf = Buffer.from(data.slice(32, 40));
  return buf.readBigUInt64LE();
}

/**
 * Read the owner pubkey from vault account data at offset 0.
 */
function readOwner(data: Uint8Array): PublicKey {
  return new PublicKey(data.slice(0, 32));
}

describe("Pinocchio: Integer Overflow / Underflow", () => {
  const owner = Keypair.generate();
  const vaultAccount = Keypair.generate();
  const vaultAccountSecure = Keypair.generate();

  describe("Vulnerable Pinocchio Implementation", () => {
    it("allows deposit overflow: balance wraps around to a small number", async () => {
      console.log("\n      OVERFLOW EXPLOIT DEMONSTRATION (Pinocchio Vulnerable):");

      // Start bankrun with the vulnerable program
      const context = await start(
        [
          {
            name: "vulnerable_integer_overflow_pinocchio",
            programId: VULNERABLE_PROGRAM_ID,
          },
        ],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Create the vault account owned by the program
      console.log("      1. Creating vault account...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: vaultAccount.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: VULNERABLE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, vaultAccount);

      await client.processTransaction(tx);
      console.log("      Vault account created");

      // Step 2: Initialize the vault
      console.log("      2. Initializing vault with owner...");
      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: vaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: owner.publicKey, isSigner: true, isWritable: false },
        ],
        data: Buffer.from([0]), // Instruction 0 = Initialize
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer, owner);

      await client.processTransaction(tx);

      let accountInfo = await client.getAccount(vaultAccount.publicKey);
      let vaultOwner = readOwner(accountInfo!.data);
      let balance = readBalance(accountInfo!.data);
      assert.ok(vaultOwner.equals(owner.publicKey), "Owner should match");
      assert.equal(balance, 0n, "Balance should be 0");
      console.log("      Vault initialized, balance:", balance.toString());

      // Step 3: Deposit 1000 to give vault a nonzero balance
      console.log("      3. Depositing 1000...");
      const depositData = Buffer.concat([Buffer.from([1]), encodeU64LE(1000n)]);
      const depositIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: vaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: owner.publicKey, isSigner: true, isWritable: false },
        ],
        data: depositData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(depositIx);
      tx.sign(payer, owner);

      await client.processTransaction(tx);

      accountInfo = await client.getAccount(vaultAccount.publicKey);
      balance = readBalance(accountInfo!.data);
      assert.equal(balance, 1000n, "Balance should be 1000");
      console.log("      Balance after deposit:", balance.toString());

      // Step 4: ATTACK - Deposit u64::MAX to cause overflow
      const U64_MAX = 18446744073709551615n;
      console.log("\n      4. ATTACK: Depositing u64::MAX (", U64_MAX.toString(), ")...");
      console.log("         Expected: 1000 + u64::MAX wraps around to 999");

      const overflowData = Buffer.concat([Buffer.from([1]), encodeU64LE(U64_MAX)]);
      const overflowIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: vaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: owner.publicKey, isSigner: true, isWritable: false },
        ],
        data: overflowData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(overflowIx);
      tx.sign(payer, owner);

      await client.processTransaction(tx);

      accountInfo = await client.getAccount(vaultAccount.publicKey);
      balance = readBalance(accountInfo!.data);
      console.log("      Balance after overflow:", balance.toString());
      console.log("      VULNERABILITY CONFIRMED: Balance wrapped around!");

      // 1000 + u64::MAX = 999 (mod 2^64)
      assert.equal(balance, 999n, "Balance should have wrapped to 999");
      console.log("      Balance is 999 instead of a huge number - overflow occurred!");
    });

    it("allows withdraw underflow: balance wraps to huge number", async () => {
      console.log("\n      UNDERFLOW EXPLOIT DEMONSTRATION (Pinocchio Vulnerable):");

      // Start a fresh bankrun context
      const context = await start(
        [
          {
            name: "vulnerable_integer_overflow_pinocchio",
            programId: VULNERABLE_PROGRAM_ID,
          },
        ],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;
      const vault = Keypair.generate();
      const vaultOwner = Keypair.generate();

      // Create and initialize vault with balance of 100
      console.log("      1. Creating and initializing vault...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: vault.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: VULNERABLE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, vault);

      await client.processTransaction(tx);

      // Initialize
      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: Buffer.from([0]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer, vaultOwner);

      await client.processTransaction(tx);

      // Deposit 100
      console.log("      2. Depositing 100...");
      const depositData = Buffer.concat([Buffer.from([1]), encodeU64LE(100n)]);
      const depositIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: depositData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(depositIx);
      tx.sign(payer, vaultOwner);

      await client.processTransaction(tx);

      let accountInfo = await client.getAccount(vault.publicKey);
      let balance = readBalance(accountInfo!.data);
      assert.equal(balance, 100n, "Balance should be 100");
      console.log("      Balance:", balance.toString());

      // Step 3: ATTACK - Withdraw 200 from balance of 100
      console.log("\n      3. ATTACK: Withdrawing 200 from balance of 100...");
      console.log("         Expected: 100 - 200 wraps to u64::MAX - 99");

      const withdrawData = Buffer.concat([Buffer.from([2]), encodeU64LE(200n)]);
      const withdrawIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: withdrawData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(withdrawIx);
      tx.sign(payer, vaultOwner);

      await client.processTransaction(tx);

      accountInfo = await client.getAccount(vault.publicKey);
      balance = readBalance(accountInfo!.data);
      console.log("      Balance after underflow:", balance.toString());
      console.log("      VULNERABILITY CONFIRMED: Balance wrapped to massive number!");

      // 100 - 200 = u64::MAX - 99 = 18446744073709551516
      const expectedBalance = 18446744073709551615n - 99n;
      assert.equal(balance, expectedBalance, "Balance should have wrapped to u64::MAX - 99");
      console.log("      Attacker now has near-u64::MAX balance via underflow!");
    });
  });

  describe("Secure Pinocchio Implementation", () => {
    it("prevents deposit overflow with checked arithmetic", async () => {
      console.log("\n      FIX DEMONSTRATION: Overflow (Pinocchio Secure):");

      // Start bankrun with the secure program
      const context = await start(
        [
          {
            name: "secure_integer_overflow_pinocchio",
            programId: SECURE_PROGRAM_ID,
          },
        ],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;
      const vault = Keypair.generate();
      const vaultOwner = Keypair.generate();

      // Create and initialize vault
      console.log("      1. Creating and initializing vault...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: vault.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: SECURE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, vault);

      await client.processTransaction(tx);

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: Buffer.from([0]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer, vaultOwner);

      await client.processTransaction(tx);
      console.log("      Vault initialized");

      // Deposit 1000 first
      console.log("      2. Depositing 1000...");
      const depositData = Buffer.concat([Buffer.from([1]), encodeU64LE(1000n)]);
      const depositIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: depositData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(depositIx);
      tx.sign(payer, vaultOwner);

      await client.processTransaction(tx);

      let accountInfo = await client.getAccount(vault.publicKey);
      let balance = readBalance(accountInfo!.data);
      assert.equal(balance, 1000n, "Balance should be 1000");
      console.log("      Balance:", balance.toString());

      // Step 3: ATTACK ATTEMPT - Deposit u64::MAX to cause overflow
      const U64_MAX = 18446744073709551615n;
      console.log("\n      3. ATTACK ATTEMPT: Depositing u64::MAX...");

      const overflowData = Buffer.concat([Buffer.from([1]), encodeU64LE(U64_MAX)]);
      const overflowIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: overflowData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(overflowIx);
      tx.sign(payer, vaultOwner);

      let attackFailed = false;
      try {
        await client.processTransaction(tx);
      } catch (error: any) {
        attackFailed = true;
        console.log("      FIX CONFIRMED: Overflow deposit rejected!");
        console.log("      Error: ArithmeticOverflow (checked_add returned None)");
      }

      assert.ok(attackFailed, "Overflow deposit should have been rejected");

      // Verify balance unchanged
      accountInfo = await client.getAccount(vault.publicKey);
      balance = readBalance(accountInfo!.data);
      assert.equal(balance, 1000n, "Balance should still be 1000");
      console.log("      Balance unchanged at:", balance.toString());
    });

    it("prevents withdraw underflow with checked arithmetic", async () => {
      console.log("\n      FIX DEMONSTRATION: Underflow (Pinocchio Secure):");

      // Start bankrun with the secure program
      const context = await start(
        [
          {
            name: "secure_integer_overflow_pinocchio",
            programId: SECURE_PROGRAM_ID,
          },
        ],
        []
      );

      const client = context.banksClient;
      const payer = context.payer;
      const vault = Keypair.generate();
      const vaultOwner = Keypair.generate();

      // Create and initialize vault
      console.log("      1. Creating and initializing vault...");
      const rentExempt = await client.getRent();
      const lamports = rentExempt.minimumBalance(BigInt(ACCOUNT_SIZE));

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: vault.publicKey,
        lamports: Number(lamports),
        space: ACCOUNT_SIZE,
        programId: SECURE_PROGRAM_ID,
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(createAccountIx);
      tx.sign(payer, vault);

      await client.processTransaction(tx);

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: Buffer.from([0]),
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer, vaultOwner);

      await client.processTransaction(tx);

      // Deposit 100
      console.log("      2. Depositing 100...");
      const depositData = Buffer.concat([Buffer.from([1]), encodeU64LE(100n)]);
      const depositIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: depositData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(depositIx);
      tx.sign(payer, vaultOwner);

      await client.processTransaction(tx);

      let accountInfo = await client.getAccount(vault.publicKey);
      let balance = readBalance(accountInfo!.data);
      assert.equal(balance, 100n, "Balance should be 100");
      console.log("      Balance:", balance.toString());

      // Step 3: ATTACK ATTEMPT - Withdraw 200 from balance of 100
      console.log("\n      3. ATTACK ATTEMPT: Withdrawing 200 from balance of 100...");

      const withdrawData = Buffer.concat([Buffer.from([2]), encodeU64LE(200n)]);
      const withdrawIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: vault.publicKey, isSigner: false, isWritable: true },
          { pubkey: vaultOwner.publicKey, isSigner: true, isWritable: false },
        ],
        data: withdrawData,
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(withdrawIx);
      tx.sign(payer, vaultOwner);

      let attackFailed = false;
      try {
        await client.processTransaction(tx);
      } catch (error: any) {
        attackFailed = true;
        console.log("      FIX CONFIRMED: Underflow withdrawal rejected!");
        console.log("      Error: InsufficientFunds (checked_sub returned None)");
      }

      assert.ok(attackFailed, "Underflow withdrawal should have been rejected");

      // Verify balance unchanged
      accountInfo = await client.getAccount(vault.publicKey);
      balance = readBalance(accountInfo!.data);
      assert.equal(balance, 100n, "Balance should still be 100");
      console.log("      Balance unchanged at:", balance.toString());
    });
  });

  describe("Summary", () => {
    it("demonstrates Pinocchio integer overflow/underflow vulnerability", () => {
      console.log("\n      PINOCCHIO INTEGER OVERFLOW/UNDERFLOW SUMMARY:");
      console.log("      ");
      console.log("      VULNERABLE: Plain arithmetic with overflow-checks = false");
      console.log("         -> let new_balance = vault.balance + amount (wraps on overflow)");
      console.log("         -> let new_balance = vault.balance - amount (wraps on underflow)");
      console.log("         -> Attacker deposits u64::MAX to wrap balance to near zero");
      console.log("         -> Attacker withdraws more than balance to get near-u64::MAX");
      console.log("      ");
      console.log("      SECURE: checked_add / checked_sub with error handling");
      console.log("         -> vault.balance.checked_add(amount).ok_or(ArithmeticOverflow)?");
      console.log("         -> vault.balance.checked_sub(amount).ok_or(InsufficientFunds)?");
      console.log("         -> Transaction fails safely on overflow/underflow");
      console.log("      ");
      console.log("      KEY LESSON (Pinocchio):");
      console.log("         In no_std Pinocchio programs, there is no safety net.");
      console.log("         overflow-checks = false in Cargo.toml means wrapping is silent.");
      console.log("         Always use checked_add, checked_sub, checked_mul explicitly!");
      console.log("         Even with overflow-checks = true, explicit checks are clearer.");
    });
  });
});
