---
title: "Agent Name Length Validation Bypass in SPIRE httpchallenge Plugin"
date: 2025-12-24
tags: ["ValidationBypass", "SPIRE", "InputValidation", "Go", "OpenSource"]
---

## TL;DR

I found a validation bypass in SPIRE's httpchallenge node attestor plugin. The 32-character agent name limit wasn't being enforced due to checking the wrong length variable. Maintainer confirmed it's a legitimate bug but classified as "Low severity" since exploitation requires specific conditions. PR merged into v1.13.1.

## Background

SPIRE (SPIFFE Runtime Environment) is a production-grade identity framework for zero-trust networks. It issues cryptographic identities (SVIDs) to workloads across heterogeneous environments. Used by major companies for service mesh, microservices auth, and workload identity.

The httpchallenge plugin is one of SPIRE's node attestation methods. During research on authentication bypass vectors, I started looking at input validation in attestation plugins.

## Finding the Bug

I was auditing validation functions in attestation plugins. The httpchallenge plugin has a `validateAgentName()` function that's supposed to enforce a 32-character limit:
```go
// pkg/server/plugin/nodeattestor/httpchallenge/httpchallenge.go:177
func validateAgentName(agentName string) error {
    l := agentNamePattern.FindAllStringSubmatch(agentName, -1)
    if len(l) != 1 || len(l[0]) == 0 || len(l[0]) > 32 {
        return status.Error(codes.InvalidArgument, "agent name is not valid")
    }
    return nil
}
```

See the problem? `len(l[0])` checks the regex submatch array length (always 1 for this pattern), not the actual agent name string length. The 32-character limit check never triggers.

## The Evidence

Testing with a simple Go program:
```go
agentNamePattern := regexp.MustCompile("^[a-zA-z]+[a-zA-Z0-9-]$")

testCases := []string{
    "a1",                                                                           // 2 chars
    "validagentname12345678901",                                                   // 31 chars
    "verylongagentnamethatshouldbetoobigandshouldnotvalidatebutprobablywill",    // 73 chars
}

for _, test := range testCases {
    l := agentNamePattern.FindAllStringSubmatch(test, -1)
    fmt.Printf("Input: %s (len=%d) | len(l[0])=%d | Should pass 32-char check: %t\n", 
        test, len(test), len(l[0]), len(l[0]) <= 32)
}
```

Output:
```
Input: a1 (len=2) | len(l[0])=1 | Should pass 32-char check: true
Input: validagentname12345678901 (len=31) | len(l[0])=1 | Should pass 32-char check: true  
Input: verylongagent... (len=73) | len(l[0])=1 | Should pass 32-char check: true
```

All pass. The 73-character name goes straight through.

## Local Testing

Built SPIRE from source and tested with real attestation:
```bash
# Build SPIRE
make build

# Configure server with httpchallenge
cat > server.conf << 'EOF'
server {
    bind_address = "127.0.0.1"
    bind_port = "8081"
    trust_domain = "test.local"
    data_dir = "/tmp/spire-test/data/server"
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/tmp/spire-test/data/server/datastore.sqlite3"
        }
    }
    NodeAttestor "http_challenge" {
        plugin_data {
            tofu = false
            allow_non_root_ports = false
        }
    }
    KeyManager "memory" {
        plugin_data = {}
    }
}
EOF

# Start server
./bin/spire-server run -config server.conf &

# Configure agent with 93-character agent name
cat > agent.conf << 'EOF'
agent {
    data_dir = "/tmp/spire-test/data/agent"
    server_address = "127.0.0.1"
    server_port = "8081"
    trust_domain = "test.local"
    trust_bundle_path = "/tmp/spire-test/conf/agent/bootstrap.crt"
}
plugins {
    NodeAttestor "http_challenge" {
        plugin_data {
            hostname = "testhost"
            agentname = "verylongagentnamethatshouldbetoobigandshouldnotvalidatebutprobablywillduetothebugwefound"
            port = 80
        }
    }
    KeyManager "disk" {
        plugin_data {
            directory = "/tmp/spire-test/data/agent"
        }
    }
    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
EOF

# Run agent
./bin/spire-agent run -config agent.conf
```

Result:

<img width="1711" height="482" alt="image" src="https://github.com/user-attachments/assets/0e93740c-f111-4921-839d-9319167b2f54" />


```
DEBU[0000] Setting up nonce handler path=/.well-known/spiffe/nodeattestor/http_challenge/verylongagentnamethatshouldbetoobigandshouldnotvalidatebutprobablywillduetothebugwefound/challenge
```

The 93-character agent name passed validation and made it into the URL path. Expected to see "agent name is not valid" but validation was completely bypassed.

## The Fix

One character change:

<img width="898" height="687" alt="image" src="https://github.com/user-attachments/assets/aab2183b-8e61-4c14-a893-593271622a99" />

```go
func validateAgentName(agentName string) error {
    l := agentNamePattern.FindAllStringSubmatch(agentName, -1)
    if len(l) != 1 || len(l[0]) == 0 || len(agentName) > 32 {  // <- changed l[0] to agentName
        return status.Error(codes.InvalidArgument, "agent name is not valid")
    }
    return nil
}
```

After the fix, tested again - 93-character name correctly rejected:
```
ERRO[0016] Invalid argument: nodeattestor(http_challenge): agent name is not valid
```

## Disclosure

Reported via email to security@spiffe.io. SPIRE maintainer responded:

<img width="1613" height="286" alt="image" src="https://github.com/user-attachments/assets/899a7088-614a-4701-9c5f-4f3268a2653e" />


> "Thanks for your interest in contributing a fix. We would welcome a pull request from you... Regarding the CVE identifier and GHSA, after reviewing it, we've assessed this as a Low severity issue rather than Medium or High. The agent name is configured in the agent config file, which we treat as a trusted input under the operator's control. The practical impact is limited as standard web server URL length limits would prevent any meaningful exploitation."

Fair assessment. The bug is real but exploitation requires the operator to configure an extremely long agent name, which isn't a typical attack scenario. No CVE assigned per their policy (Medium+ only).

Submitted [PR #6324](https://github.com/spiffe/spire/pull/6324) with the fix.

## Conclusion

This validation bypass is real and causes the intended security control to be completely ineffective, but practical exploitation is limited. The maintainers were right to classify it as Low severity since it requires operator-controlled configuration.

What I learned:

- SPIRE's node attestation architecture
- Go regex submatch behavior
- When "Low severity" is the right call
- Professional disclosure process

**Status:** [PR #6324](https://github.com/spiffe/spire/pull/6324) merged into v1.13.1

---

**Timeline:**
- September 16, 2025: Bug discovered during code audit
- September 16, 2025: Reported to security@spiffe.io
- September 16, 2025: Maintainer response , "legitimate bug, Low severity"
- September 17, 2025: PR opened and merged
- September 18, 2025: Included in v1.13.1 release

**Affected:** SPIRE versions with httpchallenge plugin
**Fix:** [v1.13.1 release](https://github.com/spiffe/spire/releases/tag/v1.13.1)
**Commit:** `1e2d9e304364e554de09cff21bfdee321ccba107`

---
