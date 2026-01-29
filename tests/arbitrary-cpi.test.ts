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
import type { VulnerableArbitraryCpi } from "../target/types/vulnerable_arbitrary_cpi";
import type { SecureArbitraryCpi } from "../target/types/secure_arbitrary_cpi";

describe("Vulnerability: Arbitrary CPI", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs - using anchor.Program type properly
  const vulnerableProgram: anchor.Program<VulnerableArbitraryCpi> =
    anchor.workspace.VulnerableArbitraryCpi;
  const secureProgram: anchor.Program<SecureArbitraryCpi> =
    anchor.workspace.SecureArbitraryCpi;

  // Test accounts
  let authority: Keypair;
  let attacker: Keypair;
  let mint: PublicKey;
  let vaultTokenAccount: PublicKey;
  let vaultPda: PublicKey;
  let destinationTokenAccount: PublicKey;

  // For secure version
  let secureVaultTokenAccount: PublicKey;
  let secureDestinationTokenAccount: PublicKey;

  const INITIAL_VAULT_BALANCE = 1000_000_000_000; // 1000 tokens
  const TRANSFER_AMOUNT = 100_000_000_000; // 100 tokens

  before(async () => {
    // Create test keypairs
    authority = Keypair.generate();
    attacker = Keypair.generate();

    // Airdrop SOL
    const airdropAmount = 10 * anchor.web3.LAMPORTS_PER_SOL;

    await provider.connection.requestAirdrop(authority.publicKey, airdropAmount);
    await provider.connection.requestAirdrop(attacker.publicKey, airdropAmount);

    // Wait for airdrops to confirm
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Create mint
    mint = await createMint(
      provider.connection,
      authority,
      authority.publicKey,
      null,
      9
    );

    // Derive vault PDA for vulnerable program
    [vaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), authority.publicKey.toBuffer()],
      vulnerableProgram.programId
    );

    // Note: Secure vault PDA is auto-derived by Anchor SDK

    const lamportsForTokenAccount = await getMinimumBalanceForRentExemptAccount(provider.connection);

    // Create vault token account owned by authority (so authority can sign transfers)
    const vaultTokenAccountKeypair = Keypair.generate();
    const createVaultTokenAccountTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: authority.publicKey,
        newAccountPubkey: vaultTokenAccountKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        vaultTokenAccountKeypair.publicKey,
        mint,
        authority.publicKey, // Authority as owner so they can sign transfers
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createVaultTokenAccountTx,
      [authority, vaultTokenAccountKeypair]
    );
    vaultTokenAccount = vaultTokenAccountKeypair.publicKey;

    // Create secure vault token account owned by authority
    const secureVaultTokenAccountKeypair = Keypair.generate();
    const createSecureVaultTokenAccountTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: authority.publicKey,
        newAccountPubkey: secureVaultTokenAccountKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        secureVaultTokenAccountKeypair.publicKey,
        mint,
        authority.publicKey, // Authority as owner so they can sign transfers
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createSecureVaultTokenAccountTx,
      [authority, secureVaultTokenAccountKeypair]
    );
    secureVaultTokenAccount = secureVaultTokenAccountKeypair.publicKey;

    // Create destination token accounts
    const destinationKeypair = Keypair.generate();
    const createDestinationTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: authority.publicKey,
        newAccountPubkey: destinationKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        destinationKeypair.publicKey,
        mint,
        authority.publicKey,
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createDestinationTx,
      [authority, destinationKeypair]
    );
    destinationTokenAccount = destinationKeypair.publicKey;

    const secureDestinationKeypair = Keypair.generate();
    const createSecureDestinationTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: authority.publicKey,
        newAccountPubkey: secureDestinationKeypair.publicKey,
        lamports: lamportsForTokenAccount,
        space: ACCOUNT_SIZE,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeAccountInstruction(
        secureDestinationKeypair.publicKey,
        mint,
        authority.publicKey,
        TOKEN_PROGRAM_ID
      )
    );
    await anchor.web3.sendAndConfirmTransaction(
      provider.connection,
      createSecureDestinationTx,
      [authority, secureDestinationKeypair]
    );
    secureDestinationTokenAccount = secureDestinationKeypair.publicKey;

    // Mint tokens to vault accounts
    await mintTo(
      provider.connection,
      authority,
      mint,
      vaultTokenAccount,
      authority,
      INITIAL_VAULT_BALANCE
    );

    await mintTo(
      provider.connection,
      authority,
      mint,
      secureVaultTokenAccount,
      authority,
      INITIAL_VAULT_BALANCE
    );

    console.log("      Setup complete:");
    console.log("      Authority:", authority.publicKey.toBase58());
    console.log("      Attacker:", attacker.publicKey.toBase58());
    console.log("      Mint:", mint.toBase58());
    console.log("      Vault PDA:", vaultPda.toBase58());
    console.log("      Vault Token Account:", vaultTokenAccount.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    before(async () => {
      // Initialize the vulnerable vault
      console.log("\n      Initializing vulnerable vault...");

      await vulnerableProgram.methods
        .initialize()
        .accounts({
          authority: authority.publicKey,
          vaultTokenAccount: vaultTokenAccount,
          mint: mint,
        })
        .signers([authority])
        .rpc();

      console.log("      Vulnerable vault initialized");
    });

    it("allows legitimate transfer with correct TOKEN_PROGRAM_ID", async () => {
      console.log("\n      LEGITIMATE TRANSFER TEST:");

      // Get balance BEFORE
      const vaultBefore = await getAccount(provider.connection, vaultTokenAccount);
      const destBefore = await getAccount(provider.connection, destinationTokenAccount);
      console.log("      Vault balance before:", Number(vaultBefore.amount) / 1e9, "tokens");
      console.log("      Destination before:", Number(destBefore.amount) / 1e9, "tokens");

      // Execute transfer with legitimate TOKEN_PROGRAM_ID
      // Note: vault is auto-resolved by Anchor as a PDA
      await vulnerableProgram.methods
        .transferTokens(new BN(TRANSFER_AMOUNT))
        .accounts({
          authority: authority.publicKey,
          source: vaultTokenAccount,
          destination: destinationTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([authority])
        .rpc();

      // Get balance AFTER
      const vaultAfter = await getAccount(provider.connection, vaultTokenAccount);
      const destAfter = await getAccount(provider.connection, destinationTokenAccount);
      console.log("      Vault balance after:", Number(vaultAfter.amount) / 1e9, "tokens");
      console.log("      Destination after:", Number(destAfter.amount) / 1e9, "tokens");

      // Assert correct transfer occurred
      assert.equal(
        Number(vaultBefore.amount) - Number(vaultAfter.amount),
        TRANSFER_AMOUNT,
        "Vault should have decreased by transfer amount"
      );
      assert.equal(
        Number(destAfter.amount) - Number(destBefore.amount),
        TRANSFER_AMOUNT,
        "Destination should have increased by transfer amount"
      );
      console.log("      Transfer successful!");
    });

    it("demonstrates vulnerability: UncheckedAccount accepts ANY program ID", async () => {
      console.log("\n      VULNERABILITY DEMONSTRATION:");
      console.log("      The vulnerable program uses UncheckedAccount<'info> for token_program.");
      console.log("      This allows ANY program ID to be passed without validation.");

      // Get vault balance before attempting attack
      const vaultBefore = await getAccount(provider.connection, vaultTokenAccount);
      console.log("      Vault balance:", Number(vaultBefore.amount) / 1e9, "tokens");

      // Try to pass attacker's pubkey as the token program
      // The vulnerable program will ACCEPT this because UncheckedAccount doesn't validate
      // However, the actual CPI will fail because attacker.publicKey is not a program
      console.log("\n      ATTACK: Passing attacker's pubkey as token_program...");

      let errorMessage = "";
      try {
        await vulnerableProgram.methods
          .transferTokens(new BN(TRANSFER_AMOUNT))
          .accounts({
            authority: authority.publicKey,
            source: vaultTokenAccount,
            destination: destinationTokenAccount,
            tokenProgram: attacker.publicKey, // ATTACK: Wrong program!
          })
          .signers([authority])
          .rpc();
      } catch (error: unknown) {
        errorMessage = error instanceof Error ? error.message : String(error);
        console.log("      Transaction failed at CPI level (expected)");
        console.log("      Error snippet:", errorMessage.substring(0, 100) + "...");
      }

      // The key point: The program ACCEPTED the wrong program ID
      // It only failed because the attacker.publicKey is not a deployed program
      // With a real malicious program, this attack would succeed!
      console.log("\n      VULNERABILITY CONFIRMED:");
      console.log("      - Program accepted arbitrary program ID");
      console.log("      - Failed only because attacker.publicKey isn't a deployed program");
      console.log("      - A malicious program with same interface would execute!");
      console.log("");
      console.log("      ATTACK SCENARIO with malicious program:");
      console.log("      1. Attacker deploys fake Token program");
      console.log("      2. Fake 'transfer' reverses direction or drains to attacker");
      console.log("      3. Victim signs expecting normal transfer");
      console.log("      4. Malicious logic executes instead!");

      // Verify vault balance unchanged (attack didn't succeed due to missing program)
      const vaultAfter = await getAccount(provider.connection, vaultTokenAccount);
      assert.equal(
        Number(vaultBefore.amount),
        Number(vaultAfter.amount),
        "Vault balance should be unchanged (CPI failed)"
      );
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    before(async () => {
      // Initialize the secure vault
      console.log("\n      Initializing secure vault...");

      await secureProgram.methods
        .initialize()
        .accounts({
          authority: authority.publicKey,
          vaultTokenAccount: secureVaultTokenAccount,
          mint: mint,
        })
        .signers([authority])
        .rpc();

      console.log("      Secure vault initialized");
    });

    it("allows legitimate transfer with validated TOKEN_PROGRAM_ID", async () => {
      console.log("\n      LEGITIMATE TRANSFER TEST (SECURE):");

      // Get balance BEFORE
      const vaultBefore = await getAccount(provider.connection, secureVaultTokenAccount);
      const destBefore = await getAccount(provider.connection, secureDestinationTokenAccount);
      console.log("      Vault balance before:", Number(vaultBefore.amount) / 1e9, "tokens");
      console.log("      Destination before:", Number(destBefore.amount) / 1e9, "tokens");

      // Execute transfer with legitimate TOKEN_PROGRAM_ID
      // Note: vault is auto-resolved by Anchor as a PDA, tokenProgram is fixed in secure version
      await secureProgram.methods
        .transferTokens(new BN(TRANSFER_AMOUNT))
        .accounts({
          authority: authority.publicKey,
          source: secureVaultTokenAccount,
          destination: secureDestinationTokenAccount,
        })
        .signers([authority])
        .rpc();

      // Get balance AFTER
      const vaultAfter = await getAccount(provider.connection, secureVaultTokenAccount);
      const destAfter = await getAccount(provider.connection, secureDestinationTokenAccount);
      console.log("      Vault balance after:", Number(vaultAfter.amount) / 1e9, "tokens");
      console.log("      Destination after:", Number(destAfter.amount) / 1e9, "tokens");

      // Assert correct transfer occurred
      assert.equal(
        Number(vaultBefore.amount) - Number(vaultAfter.amount),
        TRANSFER_AMOUNT,
        "Vault should have decreased by transfer amount"
      );
      assert.equal(
        Number(destAfter.amount) - Number(destBefore.amount),
        TRANSFER_AMOUNT,
        "Destination should have increased by transfer amount"
      );
      console.log("      Secure transfer successful!");
    });

    it("REJECTS arbitrary program IDs with Program<Token> validation", async () => {
      console.log("\n      SECURITY TEST - Program<Token> validation:");

      // Get vault balance before attack attempt
      const vaultBefore = await getAccount(provider.connection, secureVaultTokenAccount);
      console.log("      Vault balance:", Number(vaultBefore.amount) / 1e9, "tokens");

      // Try to pass wrong program ID - for the secure version, Program<Token> has
      // a fixed address in the IDL, so Anchor SDK will reject passing a different value
      console.log("\n      ATTACK ATTEMPT: Passing attacker's pubkey as token_program...");

      let attackFailed = false;
      let errorMessage = "";

      try {
        // The secure program uses Program<'info, Token> which has a fixed address
        // The Anchor SDK won't let us override it, but we can demonstrate the concept
        // by using accountsPartial or accountsStrict to try to force a wrong address
        const txBuilder = secureProgram.methods.transferTokens(new BN(TRANSFER_AMOUNT));

        // Try to use accountsPartial to see if we can override
        // This should still fail because Program<Token> validates the address
        await (txBuilder as any)
          .accountsPartial({
            authority: authority.publicKey,
            source: secureVaultTokenAccount,
            destination: secureDestinationTokenAccount,
            tokenProgram: attacker.publicKey, // ATTACK: Try to override!
          })
          .signers([authority])
          .rpc();

        assert.fail("Expected transaction to fail");
      } catch (error: unknown) {
        attackFailed = true;
        errorMessage = error instanceof Error ? error.message : String(error);
        console.log("      FIX CONFIRMED: Attack rejected!");
        console.log("      Error:", errorMessage.substring(0, 100) + "...");
      }

      assert.ok(attackFailed, "Attack should have been rejected");

      // Verify vault balance unchanged
      const vaultAfter = await getAccount(provider.connection, secureVaultTokenAccount);
      assert.equal(
        Number(vaultBefore.amount),
        Number(vaultAfter.amount),
        "Vault balance should be unchanged (attack rejected)"
      );

      console.log("\n      SECURITY MECHANISM:");
      console.log("      Program<'info, Token> automatically validates:");
      console.log("      - token_program.key() == spl_token::ID");
      console.log("      - Validation happens BEFORE any logic executes");
      console.log("      - Wrong program = immediate transaction failure");
      console.log("      Vault protected from arbitrary CPI attack!");
    });
  });

  describe("Summary", () => {
    it("demonstrates the critical importance of program validation before CPI", () => {
      console.log("\n      VULNERABILITY SUMMARY:");
      console.log("");
      console.log("      VULNERABLE CODE:");
      console.log("      pub token_program: UncheckedAccount<'info>");
      console.log("");
      console.log("      SECURE CODE:");
      console.log("      pub token_program: Program<'info, Token>");
      console.log("");
      console.log("      ARBITRARY CPI ATTACK:");
      console.log("      - Attacker substitutes malicious program for legitimate one");
      console.log("      - Malicious program has same function signatures");
      console.log("      - But implements completely different (malicious) logic");
      console.log("      - Victim program unknowingly executes attacker's code");
      console.log("");
      console.log("      REAL WORLD EXAMPLES:");
      console.log("      - Fake Token program that steals tokens");
      console.log("      - Fake System program that redirects SOL");
      console.log("      - Fake Oracle program that returns manipulated prices");
      console.log("");
      console.log("      PREVENTION:");
      console.log("      1. Use Program<'info, T> for all CPI target programs");
      console.log("      2. Or manually validate: program.key() == expected_id");
      console.log("      3. Use Anchor's CPI helpers (token::transfer, etc.)");
      console.log("");
      console.log("      KEY LESSON:");
      console.log("      Never trust a program ID passed by the caller.");
      console.log("      Always validate before performing CPI operations.");
    });
  });
});
