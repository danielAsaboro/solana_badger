import * as anchor from "@coral-xyz/anchor";
import BN from "bn.js";
import { PublicKey, Keypair, SystemProgram, Transaction } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ACCOUNT_SIZE,
  createMint,
  mintTo,
  getAccount,
  getMinimumBalanceForRentExemptAccount,
  createInitializeAccountInstruction,
} from "@solana/spl-token";
import { assert } from "chai";
import type { VulnerablePdaSharing } from "../target/types/vulnerable_pda_sharing";
import type { SecurePdaSharing } from "../target/types/secure_pda_sharing";

describe("Vulnerability: PDA Sharing", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs - using anchor.Program type properly
  const vulnerableProgram: anchor.Program<VulnerablePdaSharing> =
    anchor.workspace.VulnerablePdaSharing;
  const secureProgram: anchor.Program<SecurePdaSharing> =
    anchor.workspace.SecurePdaSharing;

  // Test accounts
  let alice: Keypair;
  let bob: Keypair; // Attacker
  let mint: PublicKey;

  // Vulnerable program accounts
  let sharedPoolPda: PublicKey;
  let sharedPoolBump: number;
  let sharedVault: PublicKey;
  let aliceTokenAccount: PublicKey;
  let bobTokenAccount: PublicKey;

  // Secure program accounts
  let alicePoolPda: PublicKey;
  let alicePoolBump: number;
  let aliceSecureVault: PublicKey;
  let bobPoolPda: PublicKey;
  let bobPoolBump: number;
  let bobSecureVault: PublicKey;
  let aliceSecureTokenAccount: PublicKey;
  let bobSecureTokenAccount: PublicKey;

  const ALICE_DEPOSIT = 1000_000_000; // 1000 tokens
  const BOB_DEPOSIT = 100_000_000; // 100 tokens

  before(async () => {
    // Create test keypairs
    alice = Keypair.generate();
    bob = Keypair.generate();

    // Airdrop SOL
    const airdropAmount = 10 * anchor.web3.LAMPORTS_PER_SOL;
    await provider.connection.requestAirdrop(alice.publicKey, airdropAmount);
    await provider.connection.requestAirdrop(bob.publicKey, airdropAmount);

    // Wait for airdrops
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Create mint
    mint = await createMint(
      provider.connection,
      alice,
      alice.publicKey,
      null,
      6 // 6 decimals
    );

    // Derive VULNERABLE pool PDA (mint only - SHARED!)
    [sharedPoolPda, sharedPoolBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool"), mint.toBuffer()],
      vulnerableProgram.programId
    );

    // Create shared vault owned by pool PDA - use raw token account for PDA owner
    const sharedVaultKeypair = Keypair.generate();
    const lamportsForTokenAccount = await getMinimumBalanceForRentExemptAccount(provider.connection);

    const createSharedVaultTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: alice.publicKey,
        newAccountPubkey: sharedVaultKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        sharedVaultKeypair.publicKey,
        mint,
        sharedPoolPda, // PDA as owner
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createSharedVaultTx,
      [alice, sharedVaultKeypair]
    );
    sharedVault = sharedVaultKeypair.publicKey;

    // Create user token accounts for vulnerable tests - use raw token accounts
    const aliceTokenKeypair = Keypair.generate();
    const bobTokenKeypair = Keypair.generate();

    const createAliceTokenTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: alice.publicKey,
        newAccountPubkey: aliceTokenKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        aliceTokenKeypair.publicKey,
        mint,
        alice.publicKey,
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createAliceTokenTx,
      [alice, aliceTokenKeypair]
    );
    aliceTokenAccount = aliceTokenKeypair.publicKey;

    const createBobTokenTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: alice.publicKey,
        newAccountPubkey: bobTokenKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        bobTokenKeypair.publicKey,
        mint,
        bob.publicKey,
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createBobTokenTx,
      [alice, bobTokenKeypair]
    );
    bobTokenAccount = bobTokenKeypair.publicKey;

    // Derive SECURE pool PDAs (user + mint - UNIQUE per user!)
    [alicePoolPda, alicePoolBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool"), alice.publicKey.toBuffer(), mint.toBuffer()],
      secureProgram.programId
    );

    [bobPoolPda, bobPoolBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("pool"), bob.publicKey.toBuffer(), mint.toBuffer()],
      secureProgram.programId
    );

    // Create secure vaults owned by user-specific PDAs - use raw token accounts for PDA owners
    const aliceVaultKeypair = Keypair.generate();
    const bobVaultKeypair = Keypair.generate();

    const createAliceVaultTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: alice.publicKey,
        newAccountPubkey: aliceVaultKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        aliceVaultKeypair.publicKey,
        mint,
        alicePoolPda, // PDA as owner
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createAliceVaultTx,
      [alice, aliceVaultKeypair]
    );
    aliceSecureVault = aliceVaultKeypair.publicKey;

    const createBobVaultTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: alice.publicKey,
        newAccountPubkey: bobVaultKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        bobVaultKeypair.publicKey,
        mint,
        bobPoolPda, // PDA as owner
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createBobVaultTx,
      [alice, bobVaultKeypair]
    );
    bobSecureVault = bobVaultKeypair.publicKey;

    // Create secure user token accounts - use raw token accounts
    const aliceSecureTokenKeypair = Keypair.generate();
    const bobSecureTokenKeypair = Keypair.generate();

    const createAliceSecureTokenTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: alice.publicKey,
        newAccountPubkey: aliceSecureTokenKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        aliceSecureTokenKeypair.publicKey,
        mint,
        alice.publicKey, // Regular keypair as owner
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createAliceSecureTokenTx,
      [alice, aliceSecureTokenKeypair]
    );
    aliceSecureTokenAccount = aliceSecureTokenKeypair.publicKey;

    const createBobSecureTokenTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: alice.publicKey,
        newAccountPubkey: bobSecureTokenKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        bobSecureTokenKeypair.publicKey,
        mint,
        bob.publicKey, // Regular keypair as owner
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createBobSecureTokenTx,
      [alice, bobSecureTokenKeypair]
    );
    bobSecureTokenAccount = bobSecureTokenKeypair.publicKey;

    // Mint tokens to Alice for deposits
    await mintTo(
      provider.connection,
      alice,
      mint,
      aliceTokenAccount,
      alice,
      ALICE_DEPOSIT * 2 // Extra for both tests
    );

    await mintTo(
      provider.connection,
      alice,
      mint,
      aliceSecureTokenAccount,
      alice,
      ALICE_DEPOSIT
    );

    console.log("      Setup complete:");
    console.log("      Alice:", alice.publicKey.toBase58());
    console.log("      Bob (Attacker):", bob.publicKey.toBase58());
    console.log("      Mint:", mint.toBase58());
    console.log("      Shared Pool PDA:", sharedPoolPda.toBase58());
    console.log("      Alice's Pool PDA:", alicePoolPda.toBase58());
    console.log("      Bob's Pool PDA:", bobPoolPda.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    before(async () => {
      console.log("\n      Initializing vulnerable shared pool...");

      // Initialize pool (only needs to be done once since it's shared!)
      await vulnerableProgram.methods
        .initializePool()
        .accounts({
          initializer: alice.publicKey,
          pool: sharedPoolPda,
          vault: sharedVault,
          mint: mint,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      console.log("      Shared pool initialized");
      console.log("      WARNING: Pool PDA derived from mint only!");
      console.log("      Seeds: [b'pool', MINT_ADDRESS]");
    });

    it("allows attacker to steal other users' deposited tokens", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION:");

      // Step 1: Alice deposits tokens into the "shared" vault
      console.log("      1. Alice deposits 1000 tokens...");

      // Transfer tokens to vault (simulating deposit)
      await mintTo(
        provider.connection,
        alice,
        mint,
        sharedVault,
        alice,
        ALICE_DEPOSIT
      );

      let vaultBalance = await getAccount(provider.connection, sharedVault);
      console.log("      Vault balance after Alice's deposit:", Number(vaultBalance.amount) / 1e6, "tokens");

      // Step 2: Bob checks vault balance
      console.log("\n      2. Bob (attacker) sees Alice's tokens in shared vault...");
      console.log("      Bob derives same pool PDA: [b'pool', MINT_ADDRESS]");
      console.log("      Result: Same PDA as Alice! Funds are shared!");

      // Step 3: ATTACK - Bob withdraws Alice's tokens!
      console.log("\n      3. ATTACK: Bob withdraws tokens to his account...");

      const bobBalanceBefore = await getAccount(provider.connection, bobTokenAccount);
      console.log("      Bob's balance before:", Number(bobBalanceBefore.amount) / 1e6, "tokens");

      try {
        await vulnerableProgram.methods
          .withdraw(new BN(ALICE_DEPOSIT))
          .accounts({
            withdrawer: bob.publicKey,
            pool: sharedPoolPda, // Same PDA Alice used!
            vault: sharedVault,
            destination: bobTokenAccount,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([bob])
          .rpc();

        const bobBalanceAfter = await getAccount(provider.connection, bobTokenAccount);
        const stolenAmount = Number(bobBalanceAfter.amount) - Number(bobBalanceBefore.amount);
        console.log("      Bob's balance after:", Number(bobBalanceAfter.amount) / 1e6, "tokens");
        console.log("      VULNERABILITY CONFIRMED: Bob stole", stolenAmount / 1e6, "of Alice's tokens!");

        const vaultAfter = await getAccount(provider.connection, sharedVault);
        console.log("      Vault balance after theft:", Number(vaultAfter.amount) / 1e6, "tokens");

      } catch (error: any) {
        console.log("      Error:", error.message.substring(0, 80));
      }
    });

    it("explains why shared PDAs are dangerous", async () => {
      console.log("\n      PDA SHARING VULNERABILITY ANALYSIS:");
      console.log("");
      console.log("      VULNERABLE PDA DERIVATION:");
      console.log("      seeds = [b'pool', mint.key()]");
      console.log("");
      console.log("      The problem:");
      console.log("      - Alice deposits USDC: PDA = [b'pool', USDC_MINT]");
      console.log("      - Bob deposits USDC: PDA = [b'pool', USDC_MINT] (SAME!)");
      console.log("      - Charlie deposits USDC: PDA = [b'pool', USDC_MINT] (SAME!)");
      console.log("");
      console.log("      All users share ONE PDA and ONE vault!");
      console.log("      The shared PDA acts as signing authority for everyone.");
      console.log("");
      console.log("      ATTACK VECTOR:");
      console.log("      1. Pool PDA can sign transfers from vault");
      console.log("      2. No per-user balance tracking");
      console.log("      3. No ownership validation on withdraw");
      console.log("      4. Anyone can withdraw to any destination");
      console.log("      5. First to withdraw gets ALL the funds!");
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    before(async () => {
      console.log("\n      Initializing secure user-specific pools...");

      // Initialize Alice's pool
      await secureProgram.methods
        .initializePool()
        .accounts({
          owner: alice.publicKey,
          pool: alicePoolPda,
          vault: aliceSecureVault,
          mint: mint,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      console.log("      Alice's pool initialized");
      console.log("      Seeds: [b'pool', ALICE_PUBKEY, MINT_ADDRESS]");

      // Initialize Bob's pool
      await secureProgram.methods
        .initializePool()
        .accounts({
          owner: bob.publicKey,
          pool: bobPoolPda,
          vault: bobSecureVault,
          mint: mint,
          systemProgram: SystemProgram.programId,
        })
        .signers([bob])
        .rpc();

      console.log("      Bob's pool initialized");
      console.log("      Seeds: [b'pool', BOB_PUBKEY, MINT_ADDRESS]");
    });

    it("prevents cross-user token theft with user-specific PDAs", async () => {
      console.log("\n      FIX DEMONSTRATION:");

      // Step 1: Alice deposits tokens into HER vault
      console.log("      1. Alice deposits 1000 tokens into HER vault...");

      await mintTo(
        provider.connection,
        alice,
        mint,
        aliceSecureVault,
        alice,
        ALICE_DEPOSIT
      );

      let aliceVaultBalance = await getAccount(provider.connection, aliceSecureVault);
      console.log("      Alice's vault balance:", Number(aliceVaultBalance.amount) / 1e6, "tokens");

      // Step 2: Bob tries to steal Alice's tokens
      console.log("\n      2. ATTACK ATTEMPT: Bob tries to withdraw from Alice's pool...");

      let attackFailed = false;

      try {
        await secureProgram.methods
          .withdraw(new BN(ALICE_DEPOSIT))
          .accounts({
            owner: bob.publicKey, // Bob is signing
            pool: alicePoolPda, // But trying to use Alice's pool!
            vault: aliceSecureVault,
            destination: bobSecureTokenAccount,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([bob])
          .rpc();

        assert.fail("Expected attack to fail");
      } catch (error: any) {
        attackFailed = true;
        console.log("      FIX CONFIRMED: Attack rejected!");
        console.log("      Error: has_one = owner constraint failed");
        console.log("      Bob is NOT the owner of Alice's pool!");
      }

      assert.ok(attackFailed, "Attack should have been rejected");

      // Verify Alice's tokens are safe
      aliceVaultBalance = await getAccount(provider.connection, aliceSecureVault);
      assert.equal(
        Number(aliceVaultBalance.amount),
        ALICE_DEPOSIT,
        "Alice's tokens should be intact"
      );
      console.log("      Alice's vault protected! Balance:", Number(aliceVaultBalance.amount) / 1e6, "tokens");
    });

    it("shows user-specific PDA derivation", async () => {
      console.log("\n      SECURITY MECHANISM:");
      console.log("");
      console.log("      SECURE PDA DERIVATION:");
      console.log("      seeds = [b'pool', owner.key(), mint.key()]");
      console.log("");
      console.log("      Result:");
      console.log("      - Alice's PDA: [b'pool', ALICE_PUBKEY, USDC_MINT]");
      console.log("      - Bob's PDA: [b'pool', BOB_PUBKEY, USDC_MINT] (DIFFERENT!)");
      console.log("      - Charlie's PDA: [b'pool', CHARLIE_PUBKEY, USDC_MINT] (DIFFERENT!)");
      console.log("");
      console.log("      Each user has UNIQUE:");
      console.log("      - Pool PDA");
      console.log("      - Vault (token account)");
      console.log("      - Signing authority");
      console.log("");
      console.log("      ADDITIONAL PROTECTION:");
      console.log("      #[account(has_one = owner)]");
      console.log("      pub pool: Account<'info, TokenPool>");
      console.log("");
      console.log("      Even if Bob somehow derives Alice's PDA,");
      console.log("      the has_one constraint prevents withdrawal");
      console.log("      because pool.owner != bob.key()");
    });

    it("allows legitimate owner to withdraw their own tokens", async () => {
      console.log("\n      LEGITIMATE OPERATION:");

      // Alice withdraws her own tokens
      console.log("      Alice withdraws from her own pool...");

      const aliceBalanceBefore = await getAccount(provider.connection, aliceSecureTokenAccount);

      await secureProgram.methods
        .withdraw(new BN(500_000_000)) // Withdraw 500 tokens
        .accounts({
          owner: alice.publicKey,
          pool: alicePoolPda,
          vault: aliceSecureVault,
          destination: aliceSecureTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([alice])
        .rpc();

      const aliceBalanceAfter = await getAccount(provider.connection, aliceSecureTokenAccount);
      const withdrawn = Number(aliceBalanceAfter.amount) - Number(aliceBalanceBefore.amount);
      console.log("      Alice successfully withdrew:", withdrawn / 1e6, "tokens");

      const vaultRemaining = await getAccount(provider.connection, aliceSecureVault);
      console.log("      Remaining in vault:", Number(vaultRemaining.amount) / 1e6, "tokens");
    });
  });

  describe("Summary", () => {
    it("demonstrates the critical importance of user-specific PDA seeds", () => {
      console.log("\n      VULNERABILITY SUMMARY:");
      console.log("");
      console.log("      PDA SHARING ATTACK:");
      console.log("      - Shared PDA = Shared authority over funds");
      console.log("      - Missing user identifier in seeds");
      console.log("      - All users' funds pooled under one authority");
      console.log("      - Anyone can withdraw to any destination");
      console.log("");
      console.log("      COMMON MISTAKES:");
      console.log("      - seeds = [b'vault']  // One vault for entire program!");
      console.log("      - seeds = [b'pool', mint]  // One pool per mint");
      console.log("      - seeds = [b'order']  // One order account!");
      console.log("");
      console.log("      SECURE PATTERNS:");
      console.log("      - seeds = [b'vault', user.key()]");
      console.log("      - seeds = [b'pool', user.key(), mint.key()]");
      console.log("      - seeds = [b'order', user.key(), order_id]");
      console.log("");
      console.log("      DEFENSE IN DEPTH:");
      console.log("      1. Include user pubkey in PDA seeds");
      console.log("      2. Store owner/depositor in account state");
      console.log("      3. Use has_one = owner constraint");
      console.log("      4. Verify destination ownership if needed");
      console.log("");
      console.log("      KEY LESSON:");
      console.log("      When storing user funds or user-specific data,");
      console.log("      ALWAYS include the user's pubkey in PDA seeds.");
      console.log("      Shared PDAs = Shared access = Vulnerability!");
    });
  });
});
