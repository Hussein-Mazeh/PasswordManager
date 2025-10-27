package vault

import "time"

// KDFConfig describes the key-derivation parameters stored in the vault header.
type KDFConfig struct {
	Name        string `json:"name"`
	MemoryMB    uint32 `json:"memoryMB"`
	Time        uint32 `json:"time"`
	Parallelism uint8  `json:"parallelism"`
	SaltLen     int    `json:"saltLen"`
	KeyLen      uint32 `json:"keyLen"`
}

// VaultHeader captures metadata persisted alongside the vault contents.
type VaultHeader struct {
	Version    int       `json:"version"`
	User       string    `json:"user"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Salt       string    `json:"salt"`
	WrapNonce  string    `json:"wrapNonce"`
	WrappedMEK string    `json:"wrappedMEK"`
	KDF        KDFConfig `json:"kdf"`
	
}
