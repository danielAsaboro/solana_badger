import * as anchor from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, Transaction } from "@solana/web3.js";
import { assert } from "chai";
import type { VulnerableSignerChecks } from "../target/types/vulnerable_signer_checks";
import type { SecureSignerChecks } from "../target/types/secure_signer_checks";

describe("Vulnerability: Missing Signer Checks", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs - using anchor.Program type properly
  const vulnerableProgram: anchor.Program<VulnerableSignerChecks> =
    anchor.workspace.VulnerableSignerChecks;
  const secureProgram: anchor.Program<SecureSignerChecks> =
    anchor.workspace.SecureSignerChecks;

  // Test accounts
  let alice: Keypair;
  let attacker: Keypair;
  let aliceAccountVuln: PublicKey;
  let aliceAccountSecure: PublicKey;

  before(async () => {
    // Create test keypairs
    alice = Keypair.generate();
    attacker = Keypair.generate();

    // Airdrop SOL to test accounts
    const airdropAmount = 2 * anchor.web3.LAMPORTS_PER_SOL;

    const aliceAirdrop = await provider.connection.requestAirdrop(
      alice.publicKey,
      airdropAmount
    );
    await provider.connection.confirmTransaction(aliceAirdrop);

    const attackerAirdrop = await provider.connection.requestAirdrop(
      attacker.publicKey,
      airdropAmount
    );
    await provider.connection.confirmTransaction(attackerAirdrop);

    // Derive PDAs for program accounts
    [aliceAccountVuln] = PublicKey.findProgramAddressSync(
      [Buffer.from("program-account"), alice.publicKey.toBuffer()],
      vulnerableProgram.programId
    );

    [aliceAccountSecure] = PublicKey.findProgramAddressSync(
      [Buffer.from("program-account"), alice.publicKey.toBuffer()],
      secureProgram.programId
    );

    console.log("      Setup complete:");
    console.log("      Alice:", alice.publicKey.toBase58());
    console.log("      Attacker:", attacker.publicKey.toBase58());
    console.log("      Vulnerable Account PDA:", aliceAccountVuln.toBase58());
    console.log("      Secure Account PDA:", aliceAccountSecure.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    it("allows attacker to steal ownership WITHOUT victim's signature", async () => {
      console.log("\n      🔥 EXPLOIT DEMONSTRATION:");

      // Step 1: Alice initializes her account
      console.log("      1. Alice initializes her account...");
      await vulnerableProgram.methods
        .initialize()
        .accounts({
          owner: alice.publicKey,
          programAccount: aliceAccountVuln,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      console.log("      ✅ Alice's account initialized");

      // Verify Alice is the owner
      const accountData = await vulnerableProgram.account.programAccount.fetch(
        aliceAccountVuln
      );
      assert.ok(
        accountData.owner.equals(alice.publicKey),
        "Alice should be the initial owner"
      );
      console.log("      ✅ Verified: Alice is the owner");

      // Step 2: Attacker attempts to change ownership WITHOUT Alice's signature
      console.log(
        "\n      2. 🚨 ATTACK: Attacker calls update_owner with Alice's key but NO signature"
      );
      console.log("         Attacker passes Alice's pubkey as 'owner' parameter");
      console.log("         But Alice does NOT sign the transaction!");

      // Create the instruction manually to bypass Anchor SDK's signer check
      // The vulnerable program accepts UncheckedAccount so it won't verify signer
      const ix = await vulnerableProgram.methods
        .updateOwner()
        .accounts({
          owner: alice.publicKey, // Attacker passes Alice's key
          programAccount: aliceAccountVuln,
          newOwner: attacker.publicKey, // Attacker's key as new owner
        })
        .instruction();

      // Mark the owner account as not a signer in the instruction
      // This simulates what the vulnerable program allows
      ix.keys.find(k => k.pubkey.equals(alice.publicKey))!.isSigner = false;

      // Create and send transaction with only attacker signing
      const tx = new Transaction().add(ix);
      tx.feePayer = attacker.publicKey;
      tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
      tx.sign(attacker);

      const txSig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(txSig);

      console.log("      ⚠️  VULNERABILITY CONFIRMED: Transaction succeeded without Alice's signature!");

      // Step 3: Verify the attacker now owns the account
      const exploitedAccount = await vulnerableProgram.account.programAccount.fetch(
        aliceAccountVuln
      );

      assert.ok(
        exploitedAccount.owner.equals(attacker.publicKey),
        "Attacker should now own the account (exploit successful)"
      );
      console.log("      💀 Alice's account has been stolen by the attacker!");
      console.log(
        "      💀 New owner:",
        exploitedAccount.owner.toBase58(),
        "(Attacker)"
      );
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    it("prevents attacker from stealing ownership - requires victim's signature", async () => {
      console.log("\n      🛡️  FIX DEMONSTRATION:");

      // Step 1: Alice initializes her account (secure version)
      console.log("      1. Alice initializes her account (secure version)...");
      await secureProgram.methods
        .initialize()
        .accounts({
          owner: alice.publicKey,
          programAccount: aliceAccountSecure,
          systemProgram: SystemProgram.programId,
        })
        .signers([alice])
        .rpc();

      console.log("      ✅ Alice's account initialized (secure version)");

      // Verify Alice is the owner
      const accountData = await secureProgram.account.programAccount.fetch(
        aliceAccountSecure
      );
      assert.ok(
        accountData.owner.equals(alice.publicKey),
        "Alice should be the owner"
      );
      console.log("      ✅ Verified: Alice is the owner");

      // Step 2: Attacker attempts to change ownership WITHOUT Alice's signature
      console.log(
        "\n      2. 🔥 ATTACK ATTEMPT: Attacker tries same exploit on secure program"
      );
      console.log("         Attacker passes Alice's pubkey without her signature");

      let exploitFailed = false;
      let errorMessage = "";

      try {
        await secureProgram.methods
          .updateOwner()
          .accounts({
            owner: alice.publicKey, // Attacker passes Alice's key
            programAccount: aliceAccountSecure,
            newOwner: attacker.publicKey, // Attacker wants to become owner
          })
          .signers([attacker]) // Only attacker signs - Alice does NOT sign!
          .rpc();

        // If we get here, the exploit succeeded (test should fail)
        assert.fail("Expected transaction to fail, but it succeeded!");
      } catch (error: any) {
        // Expected to fail!
        exploitFailed = true;
        errorMessage = error.toString();
        console.log("      ✅ FIX CONFIRMED: Transaction rejected");
        console.log("      📋 Error:", errorMessage);

        // Verify the error is about missing signature
        const errorMsg = errorMessage.toLowerCase();
        // Anchor throws different errors depending on the constraint
        // Could be "missing required signature" or "unknown signer" or similar
        const hasSignatureError =
          errorMsg.includes("signature") ||
          errorMsg.includes("signer") ||
          errorMsg.includes("unknown") ||
          errorMsg.includes("not found");

        assert.ok(
          hasSignatureError,
          `Error should mention missing signature. Got: ${errorMessage}`
        );
      }

      assert.ok(exploitFailed, "Transaction should have failed");

      // Step 3: Verify Alice still owns the account
      const stillSecureAccount = await secureProgram.account.programAccount.fetch(
        aliceAccountSecure
      );

      assert.ok(
        stillSecureAccount.owner.equals(alice.publicKey),
        "Alice should still own her account (exploit prevented)"
      );
      console.log("      🛡️  Alice's account is secure!");
      console.log(
        "      🛡️  Owner still:",
        stillSecureAccount.owner.toBase58(),
        "(Alice)"
      );
    });
  });

  describe("Summary", () => {
    it("demonstrates the critical difference between vulnerable and secure implementations", () => {
      console.log("\n      📊 VULNERABILITY SUMMARY:");
      console.log("      ");
      console.log(
        "      🔴 VULNERABLE: Uses UncheckedAccount without signer validation"
      );
      console.log(
        "         → Attacker can pass any pubkey without signature"
      );
      console.log(
        "         → has_one constraint only checks data, NOT signatures"
      );
      console.log("         → Result: Unauthorized ownership transfer");
      console.log("      ");
      console.log(
        "      🟢 SECURE: Uses Signer<'info> type for automatic validation"
      );
      console.log(
        "         → Anchor enforces signature verification automatically"
      );
      console.log("         → Transaction fails if signer doesn't sign");
      console.log("         → Result: Attack prevented");
      console.log("      ");
      console.log("      💡 KEY LESSON:");
      console.log(
        "         Always use Signer<'info> for accounts that authorize actions!"
      );
      console.log(
        "         Data validation (has_one) ≠ Signature validation (Signer)"
      );
    });
  });
});
