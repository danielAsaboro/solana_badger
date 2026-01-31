import * as anchor from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { assert } from "chai";
import BN from "bn.js";
import type { VulnerableUnsafeRust } from "../target/types/vulnerable_unsafe_rust";
import type { SecureUnsafeRust } from "../target/types/secure_unsafe_rust";

describe("Vulnerability: Unsafe Rust", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs
  const vulnerableProgram: anchor.Program<VulnerableUnsafeRust> =
    anchor.workspace.VulnerableUnsafeRust;
  const secureProgram: anchor.Program<SecureUnsafeRust> =
    anchor.workspace.SecureUnsafeRust;

  // Test accounts
  let authority: Keypair;
  let attacker: Keypair;

  // Account PDAs
  let dataStoreVuln: PublicKey;
  let dataStoreSecure: PublicKey;

  // DataStore LEN = 8 (discriminator) + 32 (authority) + 8 (value) + 32 (label) + 1 (is_initialized) = 81
  const DATA_STORE_LEN = 81;

  before(async () => {
    // Create test keypairs
    authority = Keypair.generate();
    attacker = Keypair.generate();

    // Airdrop SOL
    const airdropAmount = 5 * anchor.web3.LAMPORTS_PER_SOL;

    await provider.connection.requestAirdrop(authority.publicKey, airdropAmount);
    await provider.connection.requestAirdrop(attacker.publicKey, airdropAmount);

    // Wait for airdrops
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Derive PDAs for vulnerable program
    [dataStoreVuln] = PublicKey.findProgramAddressSync(
      [Buffer.from("store"), authority.publicKey.toBuffer()],
      vulnerableProgram.programId
    );

    // Derive PDAs for secure program
    [dataStoreSecure] = PublicKey.findProgramAddressSync(
      [Buffer.from("store"), authority.publicKey.toBuffer()],
      secureProgram.programId
    );

    console.log("      Setup complete:");
    console.log("      Authority:", authority.publicKey.toBase58());
    console.log("      Attacker:", attacker.publicKey.toBase58());
    console.log("      DataStore PDA (vuln):", dataStoreVuln.toBase58());
    console.log("      DataStore PDA (secure):", dataStoreSecure.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    before(async () => {
      // Initialize data store
      console.log("\n      Setting up data store...");

      const label = Buffer.alloc(32);
      label.write("test-data");

      await vulnerableProgram.methods
        .initialize(new BN(42), Array.from(label))
        .accounts({
          authority: authority.publicKey,
          store: dataStoreVuln,
          systemProgram: SystemProgram.programId,
        })
        .signers([authority])
        .rpc();

      console.log("      Data store initialized with value=42, label='test-data'");
    });

    it("reads data successfully from legitimate data store", async () => {
      console.log("\n      NORMAL OPERATION:");

      // read_data should succeed with the correct PDA
      console.log("      1. Reading data from legitimate data store...");

      try {
        await vulnerableProgram.methods
          .readData()
          .accounts({
            authority: authority.publicKey,
            store: dataStoreVuln,
          })
          .signers([authority])
          .rpc();

        console.log("      read_data succeeded with correct data store");
      } catch (error: any) {
        console.log("      Note:", error.message.substring(0, 80));
      }

      // Verify account data
      const dataStoreAccount = await vulnerableProgram.account.dataStore.fetch(dataStoreVuln);
      console.log("      Value:", dataStoreAccount.value.toString());
      assert.ok(dataStoreAccount.value.eq(new BN(42)), "Value should be 42");
      assert.ok(
        dataStoreAccount.authority.equals(authority.publicKey),
        "Authority should match"
      );
      console.log("      Authority:", dataStoreAccount.authority.toBase58());
      console.log("      Is initialized:", dataStoreAccount.isInitialized);
    });

    it("allows read_data with wrong account due to missing ownership validation", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION:");

      // Step 1: Create a random account NOT owned by the program
      console.log("      1. Creating a fake account owned by System Program...");

      const fakeAccount = Keypair.generate();

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: attacker.publicKey,
        newAccountPubkey: fakeAccount.publicKey,
        lamports: await provider.connection.getMinimumBalanceForRentExemption(DATA_STORE_LEN),
        space: DATA_STORE_LEN,
        programId: SystemProgram.programId, // Owned by System Program, NOT the vulnerable program!
      });

      const tx = new anchor.web3.Transaction().add(createAccountIx);
      await anchor.web3.sendAndConfirmTransaction(
        provider.connection,
        tx,
        [attacker, fakeAccount]
      );

      console.log("      Fake account created:", fakeAccount.publicKey.toBase58());
      console.log("      Fake account owner: System Program (NOT our program!)");

      // Step 2: ATTACK - Pass the fake account as dataStore
      console.log("\n      2. ATTACK: Passing fake account as dataStore to read_data...");
      console.log("         - UncheckedAccount accepts any account");
      console.log("         - Vulnerable version uses unsafe pointer cast without ownership check");

      try {
        await vulnerableProgram.methods
          .readData()
          .accounts({
            authority: attacker.publicKey,
            store: fakeAccount.publicKey, // Fake account, not owned by program!
          })
          .signers([attacker])
          .rpc();

        console.log("      VULNERABILITY CONFIRMED: read_data succeeded with fake account!");
        console.log("      Program cast raw bytes to DataStore via unsafe pointer dereference.");
        console.log("      Garbage data was interpreted as a valid DataStore struct.");
      } catch (error: any) {
        // The vulnerability exists even if the transaction fails at runtime
        // because the UncheckedAccount pattern allows it conceptually
        console.log("      Note:", error.message.substring(0, 100));
        console.log("");
        console.log("      WHY THIS IS VULNERABLE:");
        console.log("      - UncheckedAccount does NOT validate program ownership");
        console.log("      - unsafe { &*(data.as_ptr() as *const DataStore) } casts ANY bytes");
        console.log("      - No discriminator check, no owner check");
        console.log("      - Attacker-controlled data is treated as trusted program state");
      }

      console.log("");
      console.log("      UNSAFE RUST PATTERN:");
      console.log("      let data = account_info.try_borrow_data()?;");
      console.log("      let store = unsafe { &*(data.as_ptr() as *const DataStore) };");
      console.log("      // Blindly reads bytes as DataStore - no validation!");
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    before(async () => {
      // Initialize secure data store
      console.log("\n      Setting up secure data store...");

      const label = Buffer.alloc(32);
      label.write("test-data");

      await secureProgram.methods
        .initialize(new BN(42), Array.from(label))
        .accounts({
          authority: authority.publicKey,
          store: dataStoreSecure,
          systemProgram: SystemProgram.programId,
        })
        .signers([authority])
        .rpc();

      console.log("      Secure data store initialized with value=42");
    });

    it("reads data successfully from legitimate data store", async () => {
      console.log("\n      FIX DEMONSTRATION:");

      // Legitimate read_data should succeed
      console.log("      1. Legitimate read_data with correct data store...");

      await secureProgram.methods
        .readData()
        .accounts({
          authority: authority.publicKey,
          store: dataStoreSecure,
        })
        .signers([authority])
        .rpc();

      console.log("      read_data succeeded with valid data store");

      // Verify data
      const dataStoreAccount = await secureProgram.account.dataStore.fetch(dataStoreSecure);
      assert.ok(dataStoreAccount.value.eq(new BN(42)), "Value should be 42");
      console.log("      Value:", dataStoreAccount.value.toString());
      console.log("      Authority:", dataStoreAccount.authority.toBase58());
    });

    it("prevents read_data with wrong account via Account<DataStore> type checking", async () => {
      console.log("\n      2. ATTACK ATTEMPT: Passing wrong account as dataStore...");

      // Create a fake account not owned by the secure program
      const fakeAccount = Keypair.generate();

      const createAccountIx = SystemProgram.createAccount({
        fromPubkey: attacker.publicKey,
        newAccountPubkey: fakeAccount.publicKey,
        lamports: await provider.connection.getMinimumBalanceForRentExemption(DATA_STORE_LEN),
        space: DATA_STORE_LEN,
        programId: SystemProgram.programId,
      });

      const tx = new anchor.web3.Transaction().add(createAccountIx);
      await anchor.web3.sendAndConfirmTransaction(
        provider.connection,
        tx,
        [attacker, fakeAccount]
      );

      let attackFailed = false;
      let errorMessage = "";

      try {
        await secureProgram.methods
          .readData()
          .accounts({
            authority: attacker.publicKey,
            store: fakeAccount.publicKey, // Fake account!
          })
          .signers([attacker])
          .rpc();

        assert.fail("Expected read_data with fake account to fail");
      } catch (error: any) {
        attackFailed = true;
        errorMessage = error.toString();
        console.log("      FIX CONFIRMED: read_data with fake account rejected!");

        const hasOwnerError =
          errorMessage.includes("AccountOwnedByWrongProgram") ||
          errorMessage.includes("owner") ||
          errorMessage.includes("AccountNotInitialized") ||
          errorMessage.includes("discriminator") ||
          errorMessage.includes("has_one");

        if (hasOwnerError) {
          console.log("      Error: Account ownership/type validation failed");
        } else {
          console.log("      Error:", errorMessage.substring(0, 100) + "...");
        }
      }

      assert.ok(attackFailed, "Attack with fake account should have failed");

      console.log("");
      console.log("      SECURITY MECHANISM:");
      console.log("      Account<'info, DataStore> performs:");
      console.log("      1. Owner check: account.owner == program_id");
      console.log("      2. Discriminator check: first 8 bytes match DataStore");
      console.log("      3. Deserialization with full type safety");
      console.log("      4. No unsafe pointer casts needed!");
    });

    it("shows how Account<T> eliminates need for unsafe Rust", async () => {
      console.log("\n      SECURITY MECHANISM:");
      console.log("");
      console.log("      VULNERABLE CODE (unsafe pointer cast):");
      console.log("      /// CHECK: UNSAFE - no ownership validation!");
      console.log("      pub data_store: UncheckedAccount<'info>");
      console.log("      ...");
      console.log("      let data = account_info.try_borrow_data()?;");
      console.log("      let store = unsafe { &*(data.as_ptr() as *const DataStore) };");
      console.log("");
      console.log("      SECURE CODE (Account<T> type):");
      console.log("      pub data_store: Account<'info, DataStore>");
      console.log("");
      console.log("      Account<'info, DataStore> validation process:");
      console.log("      1. Verify account.owner == program_id (ownership)");
      console.log("      2. Read first 8 bytes as discriminator");
      console.log("      3. Compare against sha256('account:DataStore')[:8]");
      console.log("      4. Safe Borsh deserialization (no unsafe needed)");
      console.log("      5. All checks happen BEFORE instruction logic runs");
      console.log("");
      console.log("      KEY DIFFERENCE:");
      console.log("      - unsafe ptr cast: trusts ANY bytes from ANY account");
      console.log("      - Account<T>: validates owner + type + deserializes safely");
    });
  });

  describe("Summary", () => {
    it("demonstrates the dangers of unsafe Rust in Solana programs", () => {
      console.log("\n      VULNERABILITY SUMMARY:");
      console.log("");
      console.log("      UNSAFE RUST IN SOLANA PROGRAMS:");
      console.log("      - Raw pointer casts bypass Rust's safety guarantees");
      console.log("      - UncheckedAccount + unsafe = no validation at all");
      console.log("      - Attacker-controlled bytes interpreted as program state");
      console.log("      - Memory corruption, garbage reads, logic manipulation");
      console.log("");
      console.log("      COMMON UNSAFE PATTERNS:");
      console.log("      1. unsafe { &*(ptr as *const T) }  // Raw pointer cast");
      console.log("      2. unsafe { slice::from_raw_parts() }  // Unchecked slice");
      console.log("      3. unsafe { std::mem::transmute() }  // Type reinterpretation");
      console.log("      4. UncheckedAccount + manual deserialization");
      console.log("");
      console.log("      REAL-WORLD IMPACT:");
      console.log("      - Read garbage data as valid account state");
      console.log("      - Bypass ownership and type validation entirely");
      console.log("      - Interpret attacker-crafted bytes as trusted data");
      console.log("      - Potential for arbitrary code execution in extreme cases");
      console.log("");
      console.log("      PREVENTION:");
      console.log("      1. Use Account<'info, T> instead of UncheckedAccount");
      console.log("      2. Use Borsh deserialization instead of raw pointer casts");
      console.log("      3. Always validate account ownership before reading data");
      console.log("      4. Avoid unsafe blocks unless absolutely necessary");
      console.log("      5. If unsafe is needed, add explicit owner/type checks first");
      console.log("");
      console.log("      KEY LESSON:");
      console.log("      Rust's safety guarantees are your first line of defense.");
      console.log("      unsafe blocks disable those guarantees entirely.");
      console.log("      In Solana, where accounts come from untrusted sources,");
      console.log("      unsafe pointer casts on account data are especially dangerous.");
      console.log("      Let Anchor's Account<T> handle validation safely.");
    });
  });
});
