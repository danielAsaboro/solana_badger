# Solana Security Reference

<div align="center">

**Learn Solana Security by Example**

Educational repository demonstrating common Solana security vulnerabilities with vulnerable and secure implementations in both Anchor and Pinocchio frameworks.

[📖 Documentation](#documentation) • [🧪 Run Tests](#running-tests) • [🚀 Quick Start](#quick-start)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Anchor](https://img.shields.io/badge/Anchor-0.32.1-blueviolet)](https://www.anchor-lang.com/)
[![Pinocchio](https://img.shields.io/badge/Pinocchio-0.10.1-orange)](https://github.com/anza-xyz/pinocchio)

</div>

---

## 🎯 Purpose

Learn Solana security by seeing real exploits and their fixes. Every vulnerability includes:

- ❌ **Vulnerable implementation** - Real code with security flaws
- ✅ **Secure implementation** - Properly fixed version
- 🔍 **Detailed explanation** - Inline comments explaining the issue and fix
- 🧪 **Automated exploit tests** - Demonstrations that prove vulnerabilities work
- 📊 **Framework comparison** - Anchor vs Pinocchio implementations

## 📚 Vulnerabilities Covered

| # | Vulnerability | Severity | Anchor | Pinocchio | Tests | Docs |
|---|--------------|----------|---------|-----------|-------|------|
| 1 | [Missing Signer Checks](programs/signer-checks/) | 🔴 Critical | ✅ | ✅ | ✅ | ✅ |
| 2 | [Missing Owner Checks](programs/owner-checks/) | 🔴 Critical | ✅ | ✅ | ✅ | ✅ |
| 3 | [Arbitrary CPI](programs/arbitrary-cpi/) | 🟠 High | ✅ | ✅ | ✅ | ✅ |
| 4 | [Reinitialization Attacks](programs/reinitialization-attacks/) | 🟠 High | ✅ | ✅ | ✅ | ✅ |
| 5 | [Type Cosplay](programs/type-cosplay/) | 🟡 Medium | ✅ | ✅ | ✅ | ✅ |
| 6 | [PDA Sharing](programs/pda-sharing/) | 🟡 Medium | ✅ | ✅ | ✅ | ✅ |

Legend: ✅ Complete | 🚧 In Progress

## 🏗️ Repository Structure

```
stng/
├── programs/                  # All Solana programs (24 total)
│   ├── signer-checks/         # ✅ Missing signer validation
│   │   ├── vulnerable/
│   │   │   ├── anchor/        # ✅ Anchor vulnerable implementation
│   │   │   └── pinocchio/     # ✅ Pinocchio vulnerable implementation
│   │   └── secure/
│   │       ├── anchor/        # ✅ Anchor secure implementation
│   │       └── pinocchio/     # ✅ Pinocchio secure implementation
│   ├── owner-checks/          # ✅ Missing owner validation (4 programs)
│   ├── arbitrary-cpi/         # ✅ Unvalidated cross-program invocation (4 programs)
│   ├── reinitialization-attacks/  # ✅ Account re-initialization exploits (4 programs)
│   ├── type-cosplay/          # ✅ Account type confusion (4 programs)
│   └── pda-sharing/           # ✅ Insufficient PDA seed derivation (4 programs)
├── tests/                     # ✅ Automated exploit demonstrations (46 total)
├── badger/docs/               # ✅ Mintlify documentation site
├── exploits/                  # ✅ Standalone exploit demonstrations
└── README.md                  # ✅ This file

✅ = Complete
```

## 🚀 Quick Start

### Prerequisites

Ensure you have the following installed:

- **Rust** 1.75+ ([Install](https://rustup.rs/))
- **Solana CLI** 1.18+ ([Install](https://docs.solana.com/cli/install-solana-cli-tools))
- **Anchor** 0.30+ ([Install](https://www.anchor-lang.com/docs/installation))
- **Node.js** 18+ ([Install](https://nodejs.org/))
- **Yarn** or npm

### Installation

```bash
# Clone repository
git clone https://github.com/superteamng/solana-security-reference
cd solana-security-reference

# Install Node dependencies
npm install
# or
yarn install
```

### Building Programs

```bash
# Anchor programs
cd programs/signer-checks/vulnerable/anchor
anchor build

# Pinocchio programs
cd programs/signer-checks/vulnerable/pinocchio
cargo build-sbf
```

## 🧪 Running Tests

```bash
# Run all Anchor tests (28 tests)
anchor test

# Run all Pinocchio tests (18 tests)
npm run test:pinocchio

# Test specific Anchor vulnerability
npm run test:signer-checks

# Test specific Pinocchio vulnerability
npm run test:pinocchio:signer
npm run test:pinocchio:owner
npm run test:pinocchio:cpi
npm run test:pinocchio:reinit
npm run test:pinocchio:cosplay
npm run test:pinocchio:pda
```

### Expected Test Output

```
Vulnerability: Signer Checks

  Vulnerable Implementation
    ✓ should allow attacker to steal ownership (Anchor)
    ✓ should allow attacker to steal ownership (Pinocchio)
    ⚠️  VULNERABILITY CONFIRMED: Exploit succeeded

  Secure Implementation
    ✗ should prevent attacker from stealing ownership (Anchor)
    ✗ should prevent attacker from stealing ownership (Pinocchio)
    ✅ FIX CONFIRMED: Exploit blocked by signature validation
```

## 📖 Documentation

Comprehensive documentation with interactive examples, diagrams, and video walkthroughs is available in the `badger/docs/` directory.

### Main Learning Resources

- **[Solana Security Deep Dive](SOLANA_SECURITY_DEEP_DIVE.md)** - Complete comprehensive guide (15,000+ words)
  - All 6 vulnerabilities explained in depth
  - Real-world attack analysis (Cashio $52M exploit)
  - Framework comparison and best practices
  - Code pattern recognition guide
  - Recommended learning paths

### Quick Links

- **Getting Started**
  - [Quickstart Guide](badger/docs/quickstart.mdx)
  - [Installation](badger/docs/quickstart.mdx#installation)
  - [Building Programs](badger/docs/quickstart.mdx#building)

- **Vulnerability Deep Dives**
  - [Signer Checks](badger/docs/vulnerabilities/signer-checks.mdx) - Most common vulnerability
  - [Owner Checks](badger/docs/vulnerabilities/owner-checks.mdx) - Account substitution
  - [Arbitrary CPI](badger/docs/vulnerabilities/arbitrary-cpi.mdx) - Malicious program invocation
  - [Reinitialization](badger/docs/vulnerabilities/reinitialization-attacks.mdx) - Account takeover
  - [Type Cosplay](badger/docs/vulnerabilities/type-cosplay.mdx) - Type confusion
  - [PDA Sharing](badger/docs/vulnerabilities/pda-sharing.mdx) - Authority exploitation

- **Framework Comparisons**
  - [Anchor vs Pinocchio](badger/docs/comparisons/anchor-vs-pinocchio.mdx)
  - [Security Tradeoffs](badger/docs/comparisons/security-tradeoffs.mdx)

### Running Documentation Locally

```bash
cd badger/docs
npm install
npm run dev
# Visit http://localhost:3000
```

## 🔑 Key Learnings

### For Anchor Developers

**Security patterns:**
- Use `Signer<'info>` for accounts that must sign
- Use `Account<'info, T>` for type-safe account validation
- Use `Program<'info, T>` for validated program references
- Use `init` constraint to prevent reinitialization
- Always validate account discriminators

### For Pinocchio Developers

**Manual checks required:**
- `is_signer()` - Verify signatures
- `owner()` - Validate program ownership
- Program ID validation for CPI targets
- Discriminator checks for account types
- Initialization flag validation

### Framework Comparison Summary

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| **Type Safety** | Automatic via macros | Manual validation required |
| **Security** | Built-in checks | Developer responsibility |
| **Binary Size** | ~250 KB | ~80 KB |
| **Performance** | Good | Excellent (zero-copy) |
| **Learning Curve** | Beginner-friendly | Advanced |
| **Best For** | Most projects | Performance-critical apps |

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Issues** - Found a bug or security issue? [Open an issue](https://github.com/superteamng/solana-security-reference/issues)
2. **Improve Documentation** - Clarify explanations, fix typos, add examples
3. **Add Vulnerabilities** - Suggest or implement additional security patterns
4. **Enhance Tests** - Add more comprehensive exploit demonstrations

### Development Workflow

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/solana-security-reference
cd solana-security-reference

# Create a feature branch
git checkout -b feature/your-feature-name

# Make changes and test
anchor build
npm test

# Commit and push
git add .
git commit -m "Description of changes"
git push origin feature/your-feature-name

# Open a Pull Request
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Bounty Submission

Built for **SuperteamNG Security Bounty**

### Project Goals
- ✅ **6 vulnerability examples** with vulnerable and secure implementations (24 programs total)
- ✅ **Both Anchor and Pinocchio frameworks** - Complete implementations for all vulnerabilities
- ✅ **Comprehensive inline comments** - Every vulnerability and fix thoroughly explained
- ✅ **Per-vulnerability READMEs** - Dedicated documentation for each security issue
- ✅ **Project configuration** - package.json, tsconfig.json, .gitignore, LICENSE
- ✅ **Test suite** - Automated exploit demonstrations
  - 28 passing Anchor tests with comprehensive exploit narratives
  - 18 passing Pinocchio tests using solana-bankrun
  - **46 total tests** covering all vulnerabilities in both frameworks
- ✅ **Deep-dive article** - Complete 15,000+ word security guide
- ✅ **Documentation site** - Mintlify-powered interactive docs
- ✅ **Framework comparison** - Detailed Anchor vs Pinocchio analysis

### Credits

- **Educational Content:** [Blueshift.gg](https://blueshift.gg) - Security course materials
- **Frameworks:**
  - [Anchor](https://www.anchor-lang.com) - Type-safe Solana framework
  - [Pinocchio](https://github.com/anza-xyz/pinocchio) - Zero-copy Solana programs
- **Documentation:** [Mintlify](https://mintlify.com) - Documentation platform
- **Community:** SuperteamNG - Supporting Solana development in Nigeria

## 📚 Additional Resources

### Solana Security

- [Solana Security Best Practices](https://docs.solana.com/developers)
- [Anchor Security Guide](https://www.anchor-lang.com/docs/security)
- [Neodyme Security Workshop](https://workshop.neodyme.io/)
- [Sec3 Audit Reports](https://www.sec3.dev/)

### Learning Paths

**Beginners:**
1. Start with [Signer Checks](programs/signer-checks/) - Most common vulnerability
2. Move to [Owner Checks](programs/owner-checks/) - Related validation issue
3. Run tests to see exploits in action

**Intermediate:**
1. Study [Arbitrary CPI](programs/arbitrary-cpi/) - Cross-program attacks
2. Learn [Reinitialization Attacks](programs/reinitialization-attacks/) - Account lifecycle
3. Compare Anchor vs Pinocchio implementations
4. Modify code and experiment

**Advanced:**
1. Analyze [Type Cosplay](programs/type-cosplay/) - Type system exploits
2. Master [PDA Sharing](programs/pda-sharing/) - Seed derivation issues
3. Review Pinocchio manual validation patterns
4. Contribute new vulnerability examples

## ⭐ Show Your Support

If this repository helped you learn Solana security, please give it a star! ⭐

Your feedback helps us improve the content and reach more developers.

## 📧 Contact

- **Twitter:** [@superteamng](https://twitter.com/superteamng)
- **GitHub Issues:** [Report problems or ask questions](https://github.com/superteamng/solana-security-reference/issues)
- **Discord:** Join the SuperteamNG Discord for discussions

---

<div align="center">

**[Get Started](#quick-start)** • **[View Examples](programs/)** • **[Read Docs](badger/docs/)**

Built with ❤️ by the Solana developer community

</div>
