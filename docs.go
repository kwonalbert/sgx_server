/*
Package sgx_server implements the ISV Remote Attestation Server of
the SGX remote attestation pipeline, described in the Intel code
sample:

https://software.intel.com/en-us/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example

The most typical way to interfact with this code base is through the
SessionManager interface. The SessionManager manages the Session
interfaces based on a session id, and can create or fetch new
sessions. Each Session logically represents an SGX session. After
proper authentication, the client on the other side of the connection
is guaranteed to be an SGX device. Session also supports MACing or
encrypting messages for the SGX client, which helps protect the
integrity or confidentiality of the data.

You can configure this server (i.e., the SessionManager) using a
pretty straightforward JSON-based configuration file.
*/
package sgx_server
