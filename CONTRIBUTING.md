# Contributing to Solana Security Reference

Thank you for your interest in contributing to the Solana Security Reference! This project helps developers learn about Solana security vulnerabilities through practical examples.

## 🎯 Ways to Contribute

### 1. Report Issues
- Found a bug in the code?
- Discovered incorrect security information?
- Notice unclear documentation?

[Open an issue](https://github.com/superteamng/solana-security-reference/issues) with:
- Clear description of the problem
- Steps to reproduce (if applicable)
- Expected vs actual behavior
- Your environment (Rust version, Solana version, etc.)

### 2. Improve Documentation
- Fix typos or grammar
- Clarify confusing explanations
- Add more code comments
- Improve diagrams
- Translate to other languages

### 3. Add New Vulnerabilities
Have an idea for another security vulnerability to demonstrate?

**Requirements:**
- Must be a real Solana security pattern (not theoretical)
- Provide both vulnerable and secure implementations
- Include both Anchor and Pinocchio versions
- Add comprehensive inline comments
- Create tests demonstrating the exploit
- Write documentation page

### 4. Enhance Tests
- Add more comprehensive test cases
- Improve exploit demonstrations
- Add edge case coverage
- Improve test documentation

### 5. Create Video Content
- Record vulnerability walkthroughs
- Create framework comparison videos
- Make tutorial content

## 🚀 Getting Started

### Prerequisites
- Rust 1.75+
- Solana CLI 1.18+
- Anchor 0.30+
- Node.js 18+
- Git

### Setup Development Environment

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/solana-security-reference
cd solana-security-reference

# Install dependencies
npm install

# Build programs
./scripts/build-all.sh

# Run tests
npm test
```

## 📝 Contribution Workflow

### For Code Changes

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Make your changes**
   - Follow existing code style
   - Add inline comments explaining security implications
   - Update documentation if needed
   - Add tests for new functionality

3. **Test your changes**
   ```bash
   # Build programs
   ./scripts/build-all.sh

   # Run tests
   npm test

   # Test specific vulnerability
   npm test -- your-vulnerability
   ```

4. **Commit with descriptive messages**
   ```bash
   git add .
   git commit -m "feat: Add owner checks vulnerability demonstration"
   # or
   git commit -m "fix: Correct signer validation in Pinocchio example"
   # or
   git commit -m "docs: Improve arbitrary CPI explanation"
   ```

5. **Push and create pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open Pull Request**
   - Use the pull request template
   - Describe what changed and why
   - Link related issues
   - Add screenshots for documentation changes
   - Request review

### For Documentation Changes

1. **Edit MDX files**
   ```bash
   cd badger/docs
   # Edit files in vulnerabilities/, comparisons/, etc.
   ```

2. **Preview locally**
   ```bash
   npm run dev
   # Visit http://localhost:3000
   ```

3. **Follow the same commit and PR process**

## 🎨 Code Style Guidelines

### Rust Code
- Follow Rust official style guide (`rustfmt`)
- Use descriptive variable names
- Add comments for complex logic
- Mark vulnerabilities with `// VULNERABILITY:` comments
- Mark fixes with `// FIX:` comments

Example:
```rust
// VULNERABILITY: Missing signer check allows unauthorized access
// An attacker can pass any public key without signature validation
pub owner: UncheckedAccount<'info>,
```

### TypeScript Tests
- Use descriptive test names
- Include "vulnerable" and "secure" test sections
- Add comments explaining attack scenarios
- Use clear assertion messages

Example:
```typescript
describe("Vulnerable Implementation", () => {
  it("should allow attacker to steal ownership WITHOUT signature", async () => {
    // Attacker passes victim's public key but doesn't obtain signature
    // ...
  });
});
```

### Documentation (MDX)
- Use Mintlify components (Cards, Tabs, Accordions, etc.)
- Include Mermaid diagrams for attack flows
- Add code examples with proper syntax highlighting
- Use callouts (Warning, Tip, Info, Note) appropriately
- Keep paragraphs concise and scannable

## 🔒 Security Considerations

### When Adding Vulnerabilities
1. **Clearly mark vulnerable code**
   - Use `VULNERABILITY:` comments
   - Add `/// CHECK: INTENTIONALLY VULNERABLE` annotations
   - Name files/directories clearly (`vulnerable/`, `secure/`)

2. **Provide secure alternatives**
   - Every vulnerable implementation needs a secure version
   - Explain WHY the fix works
   - Show multiple fix approaches when applicable

3. **Document exploitation**
   - Explain how the attack works
   - Show realistic attack scenarios
   - Demonstrate impact

4. **Test thoroughly**
   - Prove exploits work on vulnerable code
   - Prove exploits fail on secure code
   - Include edge cases

### Never Commit
- Private keys or seed phrases
- Real wallet addresses
- Actual production code (only educational examples)
- Large media files (use Git LFS or external hosting)

## 🧪 Testing Requirements

All new vulnerabilities must include tests:

```typescript
describe("Vulnerability: Your Vulnerability", () => {
  describe("Vulnerable Implementation", () => {
    it("should allow exploit (Anchor)", async () => {
      // Demonstrate the attack succeeds
    });

    it("should allow exploit (Pinocchio)", async () => {
      // Same attack on Pinocchio version
    });
  });

  describe("Secure Implementation", () => {
    it("should prevent exploit (Anchor)", async () => {
      // Verify fix works - expect error
    });

    it("should prevent exploit (Pinocchio)", async () => {
      // Verify fix works - expect error
    });
  });
});
```

## 📚 Documentation Standards

### Vulnerability Pages Must Include:
- [ ] Severity level (Critical/High/Medium)
- [ ] Difficulty level (Beginner/Intermediate/Advanced)
- [ ] Clear overview of the vulnerability
- [ ] Attack flow diagram (Mermaid sequence diagram)
- [ ] Vulnerable code examples (Anchor + Pinocchio)
- [ ] Secure code examples (Anchor + Pinocchio)
- [ ] Explanation of why vulnerability exists
- [ ] Explanation of how fix works
- [ ] Real-world impact examples
- [ ] Test examples
- [ ] Security checklist
- [ ] Links to related vulnerabilities

### Use Mintlify Components:
- `<CardGroup>` for feature highlights
- `<Tabs>` for framework comparisons
- `<Accordion>` for collapsible details
- `<CodeGroup>` for multiple code examples
- `<Steps>` for sequential processes
- `<Warning>`, `<Tip>`, `<Info>`, `<Note>` for callouts
- Mermaid diagrams for flows and architecture

## 🎯 Pull Request Guidelines

### PR Title Format
- `feat: Add new vulnerability example`
- `fix: Correct security explanation`
- `docs: Improve framework comparison`
- `test: Add comprehensive exploit tests`
- `chore: Update dependencies`

### PR Description Should Include:
- **What changed:** Clear description of modifications
- **Why it changed:** Motivation for the change
- **How to test:** Steps to verify the change
- **Related issues:** Link to issues being addressed
- **Screenshots:** For UI/documentation changes
- **Checklist:**
  - [ ] Code builds successfully
  - [ ] Tests pass
  - [ ] Documentation updated
  - [ ] No security issues introduced

### Review Process
1. Automated checks run (build, tests, lint)
2. Maintainers review code and documentation
3. Changes requested or approval given
4. PR merged after approval

## 🤝 Community Guidelines

### Be Respectful
- Use welcoming and inclusive language
- Respect differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community

### Be Professional
- Keep discussions focused and on-topic
- Avoid personal attacks or inflammatory language
- Assume good intentions
- Ask questions instead of making demands

### Be Helpful
- Welcome newcomers
- Share knowledge generously
- Provide context in explanations
- Credit others' work

## 📞 Getting Help

- **Questions:** Open a [discussion](https://github.com/superteamng/solana-security-reference/discussions)
- **Bugs:** Open an [issue](https://github.com/superteamng/solana-security-reference/issues)
- **Community:** Join [SuperteamNG Discord](https://superteam.fun/ng)

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Solana security education! 🎉
