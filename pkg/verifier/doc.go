// Package verifier provides high-level IMA measurement list attestation flows.
//
// It orchestrates entry parsing, per-entry validation, PCR aggregate replay,
// optional signature checks for ima-sig, and incremental resume semantics.
package verifier
