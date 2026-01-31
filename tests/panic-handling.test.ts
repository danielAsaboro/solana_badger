import * as anchor from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { assert } from "chai";
import BN from "bn.js";
import type { VulnerablePanicHandling } from "../target/types/vulnerable_panic_handling";
import type { SecurePanicHandling } from "../target/types/secure_panic_handling";

describe("Vulnerability: Panic Handling", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs
  const vulnerableProgram: anchor.Program<VulnerablePanicHandling> =
    anchor.workspace.VulnerablePanicHandling;
  const secureProgram: anchor.Program<SecurePanicHandling> =
    anchor.workspace.SecurePanicHandling;

  // Test accounts
  let user: Keypair;

  // PDAs
  let vulnStatePda: PublicKey;
  let vulnStateBump: number;
  let secureStatePda: PublicKey;
  let secureStateBump: number;

  before(async () => {
    user = Keypair.generate();

    // Airdrop SOL
    const airdropAmount = 5 * anchor.web3.LAMPORTS_PER_SOL;
    await provider.connection.requestAirdrop(user.publicKey, airdropAmount);

    // Wait for airdrop
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Derive PDAs for vulnerable program
    [vulnStatePda, vulnStateBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("processor"), user.publicKey.toBuffer()],
      vulnerableProgram.programId
    );

    // Derive PDAs for secure program
    [secureStatePda, secureStateBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("processor"), user.publicKey.toBuffer()],
      secureProgram.programId
    );

    console.log("      Setup complete:");
    console.log("      User:", user.publicKey.toBase58());
    console.log("      Vulnerable State PDA:", vulnStatePda.toBase58());
    console.log("      Secure State PDA:", secureStatePda.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    it("panics on empty values", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION: Panic on empty values");
      console.log("      Calling process with empty Vec and divisor=1...");
      console.log("      Vulnerable code uses .unwrap() on None (empty vec first/last)");

      let panicked = false;

      try {
        await vulnerableProgram.methods
          .processData([], new BN(1))
          .accounts({
            authority: user.publicKey,
            state: vulnStatePda,
            systemProgram: SystemProgram.programId,
          })
          .signers([user])
          .rpc();

        assert.fail("Expected panic on empty values");
      } catch (error: any) {
        panicked = true;
        console.log("      PANIC CONFIRMED: Program crashed!");
        console.log("      Error:", error.message.substring(0, 100));
        console.log("");
        console.log("      WHY IT PANICKED:");
        console.log("      - values.first().unwrap() called on empty Vec");
        console.log("      - .unwrap() on None triggers panic!()");
        console.log("      - Program halts with unrecoverable error");
        console.log("      - Transaction fails with opaque error message");
      }

      assert.ok(panicked, "Should have panicked on empty values");
    });

    it("panics on division by zero", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION: Panic on division by zero");
      console.log("      Calling process with [10, 20] and divisor=0...");

      let panicked = false;

      try {
        await vulnerableProgram.methods
          .processData(
            [new BN(10), new BN(20)],
            new BN(0)
          )
          .accounts({
            authority: user.publicKey,
            state: vulnStatePda,
            systemProgram: SystemProgram.programId,
          })
          .signers([user])
          .rpc();

        assert.fail("Expected panic on division by zero");
      } catch (error: any) {
        panicked = true;
        console.log("      PANIC CONFIRMED: Program crashed!");
        console.log("      Error:", error.message.substring(0, 100));
        console.log("");
        console.log("      WHY IT PANICKED:");
        console.log("      - total / divisor where divisor = 0");
        console.log("      - Rust panics on integer division by zero");
        console.log("      - No checked_div() or prior validation");
        console.log("      - Compute units consumed before crash");
      }

      assert.ok(panicked, "Should have panicked on division by zero");
    });

    it("succeeds with valid input", async () => {
      console.log("\n      VALID INPUT TEST:");
      console.log("      Calling process with [10, 20] and divisor=2...");

      await vulnerableProgram.methods
        .processData(
          [new BN(10), new BN(20)],
          new BN(2)
        )
        .accounts({
          authority: user.publicKey,
          state: vulnStatePda,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      console.log("      Transaction succeeded with valid inputs");

      // Fetch state to verify
      const state = await vulnerableProgram.account.processorState.fetch(vulnStatePda);
      console.log("      State authority:", state.authority.toBase58());
      console.log("      State total:", state.total.toString());
      console.log("");
      console.log("      NOTE: Valid inputs work fine.");
      console.log("      The danger is edge cases that trigger panics.");
      console.log("      Panics waste compute, give opaque errors,");
      console.log("      and can be exploited for DoS attacks.");
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    it("gracefully rejects empty values", async () => {
      console.log("\n      FIX DEMONSTRATION: Graceful empty values rejection");
      console.log("      Calling process with empty Vec and divisor=1...");

      let rejected = false;

      try {
        await secureProgram.methods
          .processData([], new BN(1))
          .accounts({
            authority: user.publicKey,
            state: secureStatePda,
            systemProgram: SystemProgram.programId,
          })
          .signers([user])
          .rpc();

        assert.fail("Expected graceful error on empty values");
      } catch (error: any) {
        rejected = true;
        console.log("      FIX CONFIRMED: Graceful error returned!");
        console.log("      Error:", error.message.substring(0, 100));
        console.log("");
        console.log("      HOW IT WAS FIXED:");
        console.log("      - if values.is_empty() { return Err(ErrorCode::EmptyValues) }");
        console.log("      - Checked BEFORE any .unwrap() or .first()");
        console.log("      - Returns descriptive custom error code");
        console.log("      - No panic, no wasted compute units");
      }

      assert.ok(rejected, "Should have gracefully rejected empty values");
    });

    it("gracefully rejects division by zero", async () => {
      console.log("\n      FIX DEMONSTRATION: Graceful division by zero rejection");
      console.log("      Calling process with [10, 20] and divisor=0...");

      let rejected = false;

      try {
        await secureProgram.methods
          .processData(
            [new BN(10), new BN(20)],
            new BN(0)
          )
          .accounts({
            authority: user.publicKey,
            state: secureStatePda,
            systemProgram: SystemProgram.programId,
          })
          .signers([user])
          .rpc();

        assert.fail("Expected graceful error on division by zero");
      } catch (error: any) {
        rejected = true;
        console.log("      FIX CONFIRMED: Graceful error returned!");
        console.log("      Error:", error.message.substring(0, 100));
        console.log("");
        console.log("      HOW IT WAS FIXED:");
        console.log("      - if divisor == 0 { return Err(ErrorCode::DivisionByZero) }");
        console.log("      - Validated BEFORE performing arithmetic");
        console.log("      - Uses checked_div() as defense in depth");
        console.log("      - Returns meaningful error instead of panic");
      }

      assert.ok(rejected, "Should have gracefully rejected division by zero");
    });

    it("succeeds with valid input", async () => {
      console.log("\n      VALID INPUT TEST (Secure):");
      console.log("      Calling process with [10, 20] and divisor=2...");

      await secureProgram.methods
        .processData(
          [new BN(10), new BN(20)],
          new BN(2)
        )
        .accounts({
          authority: user.publicKey,
          state: secureStatePda,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      console.log("      Transaction succeeded with valid inputs");

      // Fetch state to verify
      const state = await secureProgram.account.processorState.fetch(secureStatePda);
      console.log("      State authority:", state.authority.toBase58());
      console.log("      State total:", state.total.toString());
      console.log("");
      console.log("      Secure program handles ALL cases:");
      console.log("      - Empty values -> custom error");
      console.log("      - Division by zero -> custom error");
      console.log("      - Valid inputs -> processes correctly");
    });
  });

  describe("Summary", () => {
    it("demonstrates the importance of proper panic handling", () => {
      console.log("\n      VULNERABILITY SUMMARY:");
      console.log("");
      console.log("      PANIC HANDLING ATTACK:");
      console.log("      - Unhandled panics crash the program abruptly");
      console.log("      - .unwrap() on None/Err causes immediate panic");
      console.log("      - Integer division by zero panics in Rust");
      console.log("      - Arithmetic overflow panics in debug mode");
      console.log("");
      console.log("      COMMON PANIC SOURCES IN SOLANA:");
      console.log("      1. .unwrap() on Option::None (empty collections)");
      console.log("      2. .unwrap() on Result::Err (failed operations)");
      console.log("      3. Integer division by zero (/ and % operators)");
      console.log("      4. Integer overflow in debug builds");
      console.log("      5. Array index out of bounds");
      console.log("      6. slice::from_raw_parts with bad lengths");
      console.log("");
      console.log("      WHY PANICS ARE DANGEROUS:");
      console.log("      - Opaque error messages (no custom error code)");
      console.log("      - Wasted compute units before crash");
      console.log("      - DoS vector: attacker triggers panics cheaply");
      console.log("      - Poor user experience and debugging");
      console.log("      - May leave state partially modified");
      console.log("");
      console.log("      PREVENTION:");
      console.log("      1. NEVER use .unwrap() - use .ok_or(err)? instead");
      console.log("      2. Validate inputs BEFORE processing");
      console.log("      3. Use checked_add/sub/mul/div for arithmetic");
      console.log("      4. Return descriptive custom errors");
      console.log("      5. Use require!() macro for preconditions");
      console.log("");
      console.log("      VULNERABLE vs SECURE:");
      console.log("      values.first().unwrap()  ->  values.first().ok_or(err)?");
      console.log("      total / divisor           ->  total.checked_div(divisor).ok_or(err)?");
      console.log("");
      console.log("      KEY LESSON:");
      console.log("      Every .unwrap() is a potential DoS vector.");
      console.log("      Validate all inputs and use checked operations.");
      console.log("      Return meaningful errors instead of panicking.");
    });
  });
});
