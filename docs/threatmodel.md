<!-- docs/threat-model.md -->

# Threat Model Outline

## 1. Assets
- Master password (human-memorized secret that gates everything)
- Password-derived key (PDK) from KDF output
- Master encryption key (MEK) used for vault data encryption
- Encrypted entries (per-account credentials, secrets, notes)
- Metadata (timestamps, identifiers, non-sensitive vault context)

## 2. Adversaries
- Disk thief with offline access to vault files
- Local malware executing in user space
- Memory dumper capturing process state
- Shoulder-surfer observing UI and keyboard input

## 3. Assumptions
- Kernel/root layer remains uncompromised
- System clock stays accurate and trustworthy

## 4. Out of Scope
- Browser autofill integrations
- Multi-device synchronization features

## 5. Phase 0 Controls (Today)
- Atomic on-disk writes to prevent partial corruption
- Restricted file permissions on vault artifacts
- Avoid logging secrets or sensitive parameters
