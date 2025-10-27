# Auth Package

This package holds authentication helpers that enforce requirements for the
user-facing master password. The policy is enforced both when the password is
first set and when it is changed.

## Files

- `policy.go` – validates a prospective master password against the current
  policy (minimum length, uppercase letter, digit, special character).

## Notes

- The validation logic returns descriptive errors so CLI code can surface a
  generic failure message.
- Run `go test ./...` from the repository root to execute the package tests
  that cover database setup and other storage behaviour.
