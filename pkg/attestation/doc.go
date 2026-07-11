// Package attestation provides attestation state management for IMA
// measurement list verification.
//
// It tracks the running PCR aggregate and the byte offset already attested,
// enabling incremental verification across multiple attestation cycles.
package attestation
