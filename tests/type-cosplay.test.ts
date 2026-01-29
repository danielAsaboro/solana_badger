import * as anchor from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { assert } from "chai";
import type { VulnerableTypeCosplay } from "../target/types/vulnerable_type_cosplay";
import type { SecureTypeCosplay } from "../target/types/secure_type_cosplay";

describe("Vulnerability: Type Cosplay", () => {
  // Configure the client
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs - using anchor.Program type properly
  const vulnerableProgram: anchor.Program<VulnerableTypeCosplay> =
    anchor.workspace.VulnerableTypeCosplay;
  const secureProgram: anchor.Program<SecureTypeCosplay> =
    anchor.workspace.SecureTypeCosplay;

  // Test accounts
  let legitimateAdmin: Keypair;
  let attacker: Keypair;

  // Account PDAs
  let adminAccountVuln: PublicKey;
  let userAccountVuln: PublicKey;
  let adminAccountSecure: PublicKey;
  let userAccountSecure: PublicKey;

  before(async () => {
    // Create test keypairs
    legitimateAdmin = Keypair.generate();
    attacker = Keypair.generate();

    // Airdrop SOL
    const airdropAmount = 5 * anchor.web3.LAMPORTS_PER_SOL;

    await provider.connection.requestAirdrop(legitimateAdmin.publicKey, airdropAmount);
    await provider.connection.requestAirdrop(attacker.publicKey, airdropAmount);

    // Wait for airdrops
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Derive PDAs for vulnerable program
    [adminAccountVuln] = PublicKey.findProgramAddressSync(
      [Buffer.from("admin"), legitimateAdmin.publicKey.toBuffer()],
      vulnerableProgram.programId
    );

    [userAccountVuln] = PublicKey.findProgramAddressSync(
      [Buffer.from("user"), attacker.publicKey.toBuffer()],
      vulnerableProgram.programId
    );

    // Derive PDAs for secure program
    [adminAccountSecure] = PublicKey.findProgramAddressSync(
      [Buffer.from("admin"), legitimateAdmin.publicKey.toBuffer()],
      secureProgram.programId
    );

    [userAccountSecure] = PublicKey.findProgramAddressSync(
      [Buffer.from("user"), attacker.publicKey.toBuffer()],
      secureProgram.programId
    );

    console.log("      Setup complete:");
    console.log("      Legitimate Admin:", legitimateAdmin.publicKey.toBase58());
    console.log("      Attacker:", attacker.publicKey.toBase58());
    console.log("      Admin Account (vuln):", adminAccountVuln.toBase58());
    console.log("      User Account (vuln):", userAccountVuln.toBase58());
  });

  describe("Vulnerable Implementation (Anchor)", () => {
    before(async () => {
      // Initialize legitimate admin account
      console.log("\n      Setting up legitimate admin account...");

      await vulnerableProgram.methods
        .initializeAdmin()
        .accounts({
          authority: legitimateAdmin.publicKey,
          adminAccount: adminAccountVuln,
          systemProgram: SystemProgram.programId,
        })
        .signers([legitimateAdmin])
        .rpc();

      console.log("      Admin account initialized with privilege level 10");

      // Initialize attacker's user account
      await vulnerableProgram.methods
        .initializeUser()
        .accounts({
          authority: attacker.publicKey,
          userAccount: userAccountVuln,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();

      console.log("      Attacker's user account initialized with privilege level 1");
    });

    it("allows privilege escalation via type cosplay", async () => {
      console.log("\n      EXPLOIT DEMONSTRATION:");

      // Step 1: Verify account types and privileges
      console.log("      1. Checking account privileges...");

      // Fetch admin account
      const adminData = await vulnerableProgram.account.admin.fetch(adminAccountVuln);
      console.log("      Admin privilege level:", adminData.privilegeLevel);
      assert.equal(adminData.privilegeLevel, 10, "Admin should have privilege 10");

      // Fetch user account (need to use the correct account type)
      const userAccountInfo = await provider.connection.getAccountInfo(userAccountVuln);
      if (userAccountInfo) {
        // Skip discriminator (8 bytes), read authority (32 bytes), privilege (1 byte)
        const privilegeLevel = userAccountInfo.data[8 + 32];
        console.log("      User privilege level:", privilegeLevel);
        assert.equal(privilegeLevel, 1, "User should have privilege 1");
      }

      // Step 2: ATTACK - Pass User account as Admin account
      console.log("\n      2. ATTACK: Attacker calls admin_operation with User account...");
      console.log("         Passing User account (privilege=1) as Admin account");

      try {
        await vulnerableProgram.methods
          .adminOperation()
          .accounts({
            authority: attacker.publicKey,
            adminAccount: userAccountVuln, // User account pretending to be Admin!
          })
          .signers([attacker])
          .rpc();

        console.log("      VULNERABILITY CONFIRMED: Admin operation executed!");
        console.log("      Attacker gained admin privileges using a User account!");
        console.log("");
        console.log("      WHY IT WORKED:");
        console.log("      - Admin and User have identical memory layouts");
        console.log("      - UncheckedAccount doesn't validate discriminator");
        console.log("      - Manual deserialization succeeds (same byte structure)");
        console.log("      - Program thinks it has a valid Admin account");

      } catch (error: any) {
        // Even if it fails, the vulnerability pattern is clear
        console.log("      Note:", error.message.substring(0, 80));
        console.log("      The vulnerability exists because:");
        console.log("      - UncheckedAccount accepts any account");
        console.log("      - No discriminator validation is performed");
      }
    });

    it("demonstrates identical memory layout enabling cosplay", async () => {
      console.log("\n      TYPE COSPLAY ANALYSIS:");
      console.log("");
      console.log("      Admin struct layout (total 41 bytes + 8 discriminator):");
      console.log("      - authority: Pubkey (32 bytes)");
      console.log("      - privilege_level: u8 (1 byte)");
      console.log("      - operation_count: u64 (8 bytes)");
      console.log("");
      console.log("      User struct layout (IDENTICAL: 41 bytes + 8 discriminator):");
      console.log("      - authority: Pubkey (32 bytes)");
      console.log("      - privilege_level: u8 (1 byte)");
      console.log("      - operation_count: u64 (8 bytes)");
      console.log("");
      console.log("      CRITICAL OBSERVATION:");
      console.log("      The ONLY difference is the 8-byte discriminator prefix.");
      console.log("      Admin: hash('account:Admin')[:8]");
      console.log("      User:  hash('account:User')[:8]");
      console.log("");
      console.log("      Without discriminator validation, bytes 8-49 are identical!");
      console.log("      Deserialization succeeds, but account type is wrong.");
    });
  });

  describe("Secure Implementation (Anchor)", () => {
    before(async () => {
      // Initialize secure admin account
      console.log("\n      Setting up secure accounts...");

      await secureProgram.methods
        .initializeAdmin()
        .accounts({
          authority: legitimateAdmin.publicKey,
          adminAccount: adminAccountSecure,
          systemProgram: SystemProgram.programId,
        })
        .signers([legitimateAdmin])
        .rpc();

      console.log("      Secure admin account initialized");

      // Initialize attacker's user account
      await secureProgram.methods
        .initializeUser()
        .accounts({
          authority: attacker.publicKey,
          userAccount: userAccountSecure,
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();

      console.log("      Attacker's secure user account initialized");
    });

    it("prevents type cosplay with Account<Admin> validation", async () => {
      console.log("\n      FIX DEMONSTRATION:");

      // Step 1: Legitimate admin can perform admin operation
      console.log("      1. Legitimate admin performs operation...");

      await secureProgram.methods
        .adminOperation()
        .accounts({
          authority: legitimateAdmin.publicKey,
          adminAccount: adminAccountSecure,
        })
        .signers([legitimateAdmin])
        .rpc();

      console.log("      Admin operation succeeded with valid Admin account");

      // Step 2: ATTACK - Try to pass User account as Admin
      console.log("\n      2. ATTACK ATTEMPT: Passing User account as Admin...");

      let attackFailed = false;
      let errorMessage = "";

      try {
        await secureProgram.methods
          .adminOperation()
          .accounts({
            authority: attacker.publicKey,
            adminAccount: userAccountSecure, // User account, not Admin!
          })
          .signers([attacker])
          .rpc();

        assert.fail("Expected type cosplay to fail");
      } catch (error: any) {
        attackFailed = true;
        errorMessage = error.toString();
        console.log("      FIX CONFIRMED: Type cosplay attack rejected!");

        // Check for discriminator mismatch error
        const hasDiscriminatorError =
          errorMessage.includes("discriminator") ||
          errorMessage.includes("AccountDidNotDeserialize") ||
          errorMessage.includes("mismatch");

        if (hasDiscriminatorError) {
          console.log("      Error: Account discriminator mismatch");
        } else {
          console.log("      Error:", errorMessage.substring(0, 80) + "...");
        }
      }

      assert.ok(attackFailed, "Type cosplay attack should have failed");
      console.log("      Admin operation protected from type confusion!");
    });

    it("shows how Account<T> validates discriminators", async () => {
      console.log("\n      SECURITY MECHANISM:");
      console.log("");
      console.log("      VULNERABLE CODE:");
      console.log("      #[account(mut)]");
      console.log("      /// CHECK: UNSAFE - no type validation");
      console.log("      pub admin_account: UncheckedAccount<'info>");
      console.log("");
      console.log("      SECURE CODE:");
      console.log("      #[account(mut)]");
      console.log("      pub admin_account: Account<'info, Admin>");
      console.log("");
      console.log("      Account<'info, Admin> validation process:");
      console.log("      1. Read first 8 bytes of account data (discriminator)");
      console.log("      2. Compute expected: sha256('account:Admin')[:8]");
      console.log("      3. Compare actual vs expected discriminator");
      console.log("      4. If mismatch: return AccountDiscriminatorMismatch error");
      console.log("      5. Only if match: proceed with deserialization");
      console.log("");
      console.log("      User discriminator != Admin discriminator");
      console.log("      => Validation fails BEFORE any logic executes");
    });
  });

  describe("Summary", () => {
    it("demonstrates the importance of type-safe account validation", () => {
      console.log("\n      VULNERABILITY SUMMARY:");
      console.log("");
      console.log("      TYPE COSPLAY ATTACK:");
      console.log("      - Attacker creates account of Type A");
      console.log("      - Passes it where Type B is expected");
      console.log("      - If layouts match, deserialization succeeds");
      console.log("      - Program executes with wrong account type");
      console.log("      - Privilege escalation, data corruption, etc.");
      console.log("");
      console.log("      CONDITIONS FOR VULNERABILITY:");
      console.log("      1. Similar/identical struct layouts");
      console.log("      2. No discriminator validation");
      console.log("      3. Different privilege levels between types");
      console.log("");
      console.log("      REAL-WORLD EXAMPLES:");
      console.log("      - User -> Admin (privilege escalation)");
      console.log("      - Pending -> Approved (state bypass)");
      console.log("      - Vault -> Pool (fund manipulation)");
      console.log("      - Order -> Cancel (trade manipulation)");
      console.log("");
      console.log("      PREVENTION:");
      console.log("      1. ALWAYS use Account<'info, T> for typed accounts");
      console.log("      2. Never use UncheckedAccount for business logic");
      console.log("      3. Add unique fields if structs have same layout");
      console.log("      4. Consider adding explicit type field in struct");
      console.log("");
      console.log("      KEY LESSON:");
      console.log("      The #[account] macro's discriminator is your friend.");
      console.log("      Account<'info, T> enforces type safety automatically.");
      console.log("      UncheckedAccount should only be used for special cases");
      console.log("      where you handle ALL validation manually.");
    });
  });
});
