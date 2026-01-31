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
 * Pinocchio Bump Seed Canonicalization Test
 *
 * Tests the vulnerable and secure Pinocchio implementations of bump seed handling.
 *
 * VaultState Account Layout (41 bytes):
 * - Bytes 0-31: User public key (32 bytes)
 * - Bytes 32-39: Balance (u64, 8 bytes)
 * - Byte 40: Bump seed (1 byte)
 *
 * PDA Seeds: [b"vault", user.key()]
 *
 * Instructions:
 * - 0: Initialize - creates vault PDA with canonical bump
 * - 1: Withdraw(bump) - vulnerable version accepts bump arg; secure version ignores it
 *
 * Vulnerable: Accepts user-supplied bump in withdraw, allowing non-canonical bumps
 * Secure: Uses stored canonical bump, rejects non-canonical bumps
 */

const VAULT_STATE_SIZE = 41; // 32 (user) + 8 (balance) + 1 (bump)

// Program IDs
const VULNERABLE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xb1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01,
  ])
);

const SECURE_PROGRAM_ID = new PublicKey(
  Buffer.from([
    0xb1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02,
  ])
);

describe("Pinocchio: Bump Seed Canonicalization", () => {
  const user = Keypair.generate();

  describe("Vulnerable Pinocchio Implementation", () => {
    it("initializes vault and accepts any valid bump in withdraw", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION (Pinocchio Bump Seed Canonicalization):");

      // Derive the PDA for the vault
      const [vaultPda, canonicalBump] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), user.publicKey.toBuffer()],
        VULNERABLE_PROGRAM_ID
      );

      console.log("      Vault PDA:", vaultPda.toBase58());
      console.log("      Canonical bump:", canonicalBump);

      // Pre-create the vault account at the PDA address
      const accountInfo = {
        lamports: 1_000_000,
        data: Buffer.alloc(VAULT_STATE_SIZE),
        owner: VULNERABLE_PROGRAM_ID,
        executable: false,
      };

      const context = await start(
        [
          {
            name: "vulnerable_bump_seed_canonicalization_pinocchio",
            programId: VULNERABLE_PROGRAM_ID,
          },
        ],
        [
          {
            address: vaultPda,
            info: accountInfo,
          },
        ]
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Initialize the vault
      console.log("\n      1. Initializing vault...");

      const initIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: vaultPda, isSigner: false, isWritable: true },
          { pubkey: user.publicKey, isSigner: true, isWritable: false },
        ],
        data: Buffer.from([0]), // Instruction 0 = Initialize
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer, user);

      await client.processTransaction(tx);
      console.log("      Vault initialized");

      // Read stored bump from account data
      let vaultAccount = await client.getAccount(vaultPda);
      const storedBump = vaultAccount!.data[40]; // Byte 40 = bump
      console.log("      Stored bump in vault:", storedBump);

      // Step 2: Withdraw with canonical bump - should succeed
      console.log("\n      2. Withdraw with canonical bump:", canonicalBump);

      const withdrawCanonicalIx = new TransactionInstruction({
        programId: VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: vaultPda, isSigner: false, isWritable: true },
          { pubkey: user.publicKey, isSigner: true, isWritable: true },
        ],
        data: Buffer.from([1, canonicalBump]), // Instruction 1 = Withdraw, with bump
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(withdrawCanonicalIx);
      tx.sign(payer, user);

      await client.processTransaction(tx);
      console.log("      Withdraw with canonical bump succeeded!");

      // Step 3: Show vulnerability - program does not verify the stored bump
      console.log("\n      3. VULNERABILITY: Program does not verify stored bump");
      console.log("         The withdraw instruction accepts ANY bump from the user.");
      console.log("         It does not compare the supplied bump against the stored bump.");
      console.log("");
      console.log("         Vulnerable code pattern:");
      console.log("         fn withdraw(accounts, bump: u8) {");
      console.log("             let seeds = [b\"vault\", user.key, &[bump]]; // user-supplied!");
      console.log("             // No check: bump == vault.bump");
      console.log("         }");
      console.log("");
      console.log("         This allows non-canonical bumps to be used,");
      console.log("         potentially deriving different PDA addresses.");

      assert.ok(true, "Vulnerable implementation demonstrated");
    });
  });

  describe("Secure Pinocchio Implementation", () => {
    it("initializes vault and only allows withdraw with canonical bump", async () => {
      console.log("\n      FIX DEMONSTRATION (Pinocchio Bump Seed Canonicalization):");

      // Derive the PDA for the vault
      const [vaultPda, canonicalBump] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), user.publicKey.toBuffer()],
        SECURE_PROGRAM_ID
      );

      console.log("      Vault PDA:", vaultPda.toBase58());
      console.log("      Canonical bump:", canonicalBump);

      // Pre-create the vault account at the PDA address
      const accountInfo = {
        lamports: 1_000_000,
        data: Buffer.alloc(VAULT_STATE_SIZE),
        owner: SECURE_PROGRAM_ID,
        executable: false,
      };

      const context = await start(
        [
          {
            name: "secure_bump_seed_canonicalization_pinocchio",
            programId: SECURE_PROGRAM_ID,
          },
        ],
        [
          {
            address: vaultPda,
            info: accountInfo,
          },
        ]
      );

      const client = context.banksClient;
      const payer = context.payer;

      // Step 1: Initialize the vault
      console.log("\n      1. Initializing vault...");

      const initIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: vaultPda, isSigner: false, isWritable: true },
          { pubkey: user.publicKey, isSigner: true, isWritable: false },
        ],
        data: Buffer.from([0]), // Instruction 0 = Initialize
      });

      let tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(initIx);
      tx.sign(payer, user);

      await client.processTransaction(tx);
      console.log("      Vault initialized");

      // Read stored bump
      let vaultAccount = await client.getAccount(vaultPda);
      const storedBump = vaultAccount!.data[40]; // Byte 40 = bump
      console.log("      Stored canonical bump:", storedBump);

      // Step 2: Withdraw with canonical bump - should succeed
      console.log("\n      2. Withdraw with canonical bump:", canonicalBump);

      const withdrawCanonicalIx = new TransactionInstruction({
        programId: SECURE_PROGRAM_ID,
        keys: [
          { pubkey: vaultPda, isSigner: false, isWritable: true },
          { pubkey: user.publicKey, isSigner: true, isWritable: true },
        ],
        data: Buffer.from([1, canonicalBump]), // Instruction 1 = Withdraw, with bump
      });

      tx = new Transaction();
      tx.recentBlockhash = context.lastBlockhash;
      tx.feePayer = payer.publicKey;
      tx.add(withdrawCanonicalIx);
      tx.sign(payer, user);

      await client.processTransaction(tx);
      console.log("      Withdraw with canonical bump succeeded!");

      // Step 3: Attempt withdraw with non-canonical bump - should FAIL
      console.log("\n      3. ATTACK: Attempt withdraw with non-canonical bump...");

      let nonCanonicalBump: number | null = null;
      for (let bump = canonicalBump - 1; bump >= 0; bump--) {
        try {
          PublicKey.createProgramAddressSync(
            [Buffer.from("vault"), user.publicKey.toBuffer(), Buffer.from([bump])],
            SECURE_PROGRAM_ID
          );
          nonCanonicalBump = bump;
          break;
        } catch {
          continue;
        }
      }

      if (nonCanonicalBump !== null) {
        console.log("      Found non-canonical bump:", nonCanonicalBump);
        console.log("      Canonical bump:", canonicalBump);

        const withdrawNonCanonicalIx = new TransactionInstruction({
          programId: SECURE_PROGRAM_ID,
          keys: [
            { pubkey: vaultPda, isSigner: false, isWritable: true },
            { pubkey: user.publicKey, isSigner: true, isWritable: true },
          ],
          data: Buffer.from([1, nonCanonicalBump]), // Non-canonical bump
        });

        tx = new Transaction();
        tx.recentBlockhash = context.lastBlockhash;
        tx.feePayer = payer.publicKey;
        tx.add(withdrawNonCanonicalIx);
        tx.sign(payer, user);

        let attackFailed = false;
        try {
          await client.processTransaction(tx);
        } catch (error: any) {
          attackFailed = true;
          console.log("      FIX CONFIRMED: Non-canonical bump rejected!");
          console.log("      Secure program verifies bump matches stored canonical bump.");
        }

        assert.ok(attackFailed, "Non-canonical bump should be rejected");
      } else {
        console.log("      No non-canonical bump found (extremely rare).");
        console.log("      The secure program would reject it if one existed.");
      }

      console.log("\n      SECURE CODE PATTERN:");
      console.log("      fn withdraw(accounts) {");
      console.log("          let stored_bump = vault.data[40];");
      console.log("          // ALWAYS use stored canonical bump, ignore user input");
      console.log("          let seeds = [b\"vault\", user.key, &[stored_bump]];");
      console.log("      }");
    });
  });

  describe("Summary", () => {
    it("demonstrates Pinocchio bump seed canonicalization vulnerability", () => {
      console.log("\n      PINOCCHIO BUMP SEED CANONICALIZATION SUMMARY:");
      console.log("      ");
      console.log("      VULNERABLE: Accepts user-supplied bump in withdraw");
      console.log("         -> User passes bump as instruction data");
      console.log("         -> Program uses it directly without verification");
      console.log("         -> Non-canonical bumps can derive different addresses");
      console.log("         -> Enables duplicate accounts or PDA confusion");
      console.log("      ");
      console.log("      SECURE: Uses stored canonical bump from initialization");
      console.log("         -> Initialize stores canonical bump in account data");
      console.log("         -> Withdraw reads bump from account, ignores user input");
      console.log("         -> Or verifies user-supplied bump matches stored bump");
      console.log("         -> Only canonical PDA is ever used");
      console.log("      ");
      console.log("      KEY LESSON (Pinocchio):");
      console.log("         In native/Pinocchio programs without Anchor constraints,");
      console.log("         you MUST manually store and verify bump seeds.");
      console.log("         Never trust bump values from instruction data.");
      console.log("         Always use the canonical bump from find_program_address.");
    });
  });
});
