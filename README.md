# Git Proxy

A Go SSH server that routes Git repositories by registered SSH key and exact repository path. Includes a locally served Tailwind CSS web interface and a restricted SSH management terminal. Repository contents stream directly between the client and upstream SSH server: no clones, pack-file staging, repository disk quotas, or local command execution.

## Run

Requires Go 1.26 or newer. The compiled Tailwind stylesheet is embedded; Node is only required to modify/rebuild the UI.

```sh
go build -o bin/git-proxy ./cmd/git-proxy
./bin/git-proxy -data ./data -ssh 0.0.0.0:2222 -http 127.0.0.1:8080
```

Open `http://127.0.0.1:8080`. Read the one-time setup token from `data/setup-token` and use it to register the first administrator with a username and a password of at least 12 bytes. The first registration is atomic; subsequent visitors must log in. The token file is removed once setup completes. No SSH keys can connect before an administrator registers them.

The data directory is mode `0700`; the SQLite database, generated Ed25519 SSH host key, and setup token are mode `0600`. Keep the directory persistent and private. Back up the database with SQLite's backup API or stop the service before copying the directory, including SQLite WAL files. Losing the host key changes the server's SSH identity. Web sessions and recent activity are in memory and reset on restart.

For remote web access use HTTPS, either directly:

```sh
./bin/git-proxy -http 0.0.0.0:8443 -tls-cert cert.pem -tls-key key.pem
```

or a TLS reverse proxy forwarding the original `Host`, with the application bound to loopback and `-secure-cookie`. That flag also selects HTTPS for form-origin validation behind the reverse proxy. Do not expose unencrypted web password login publicly.

## Register users, keys, and routes

1. In **People**, an administrator creates member or administrator accounts. There is no public signup after initial setup. Administrators see and manage every user, key, route, and activity entry; members manage their own keys, routes, and password.
2. Add an ordinary SSH public key in **SSH keys**, selecting its owner when signed in as an administrator. Each fingerprint belongs to one user. Certificates and authorized_keys options are rejected.
3. In **Repository routes**, choose the owner, a specific key or all of that owner's keys, the exact source repository path, upstream hostname/IP, port, SSH username, repository path, and trusted SHA256 host-key fingerprint. Optionally mark the route read-only.

For example, an owner can configure:

| Registered key | Source path | Upstream | Upstream repository |
| --- | --- | --- | --- |
| Key A | `xxxx/project.git` | `git@host-a:22` | `team/project.git` |
| Key A | `xxxx/tools.git` | `git@host-b:2222` | `other/tools.git` |
| Key B | `xxxx/project.git` | `git@host-c:22` | `/srv/git/project.git` |

A specific-key route takes precedence over an all-owner-keys route for the same source. The SSH username at the proxy does not select an account: the registered key selects its owner. Paths are case-sensitive; `.git` is significant. A single leading slash added by Git's `ssh://` syntax is removed from the virtual source. Paths contain letters, digits, `.`, `_`, `-`, and `/`, with no empty, `.` or `..` components. Upstream paths may have one leading slash; spaces, tildes, and shell syntax are intentionally unsupported.

To configure or replace a host identity from the control panel, open **Repository routes → Edit route**, check the upstream **Host** and **Port**, then click **Fetch host identity**. The panel displays the SSH key algorithm, public key, SHA256 fingerprint, and whether it matches the current field. Compare the result with a trusted source, click **Use this fingerprint**, then **Save route changes**. Fetching does not alter the route or authenticate upstream; selecting fills the field, and saving applies the pin. Changing the host or port clears the fetched result so an identity cannot be selected for a different destination.

Obtain the upstream host fingerprint through a trusted administrator or the hosting provider's published fingerprints. For a host you control, inspect its public host key directly:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Unverified `ssh-keyscan` output alone does not establish trust. Each route pins one host key; update the pin in the web interface or TUI when the upstream rotates it. The proxy does not silently trust unknown or changed upstream identities.

## Use Git

Load the upstream credentials into your local SSH agent and register the proxy identity's public key in the application. The identity used to enter the proxy and the agent's upstream identity may be different.

```sh
ssh-add ~/.ssh/id_ed25519
```

Add a client SSH configuration entry:

```sshconfig
Host git-proxy
    HostName your-proxy.example.com
    Port 2222
    User git
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    ForwardAgent yes
```

Verify the proxy's host key against the fingerprint printed at service startup. Then:

```sh
git clone git-proxy:xxxx/project.git
git -C project fetch
git -C project push origin main
git archive --remote=git-proxy:xxxx/project.git HEAD > source.tar
```

The proxy supports `git-upload-pack`, `git-receive-pack`, and `git-upload-archive`. Clone, fetch, pull, push, and archive use bounded SSH buffers and backpressure. Git protocol version 1/2 requests are forwarded when the client sends `GIT_PROTOCOL`; upstream servers may decline that environment request and use the default protocol. The upstream must support the requested Git operation; some hosted providers disable remote archive.

Read-only routes reject `git-receive-pack`. The upstream server remains responsible for repository authorization, hooks, and Git policy. Git LFS HTTP transfers, submodule remotes, and other external protocols use their own configured connections and are not intercepted by this SSH proxy.

The **Overview** page refreshes activity every few seconds: operation, source/destination, state, transferred bytes, and errors. It retains active streams and up to 200 completed entries in memory. Byte counts include Git protocol data and upstream stderr, not just repository payload. Activity metadata is not a persistent audit log and repository contents are never recorded.

## Restricted SSH terminal

```sh
ssh -t git-proxy
```

The terminal is a management interface, not an operating-system shell. `help` lists available commands:

```text
mappings         mapping add     mapping edit     mapping delete
keys             key add         key delete       activity
password         quit
```

Administrators also get `users`, `user add`, `user edit`, `user delete`, `user password`, `settings`, and `settings edit`. Commands prompt for fields; list commands print IDs used by edit/delete prompts. Password input is hidden. Agent forwarding is required for Git, not for management. No SFTP, SCP, arbitrary exec, TCP forwarding, or subsystem access is exposed. The server never starts a local process for production sessions.

## Reconfiguration and access

Routes, keys, users, passwords, banner, concurrent sessions per user, and session lifetime can be changed live through either management interface. Users may hold multiple keys and routes. Removing a key also removes routes bound to it. Deleting a user removes their keys and routes. The last enabled administrator cannot be deleted, disabled, or demoted. Password changes invalidate that user's existing web sessions, including changes made through SSH.

Permissions and key membership are checked for every new SSH session and TUI command. Routes and read-only policy are resolved when each Git operation starts. Existing Git streams retain their selected destination and policy until completion or timeout; changes affect subsequent operations. Web role/disabled/password state is rechecked on every request.

SSH has a ten-minute connection idle timeout and a 24-hour hard connection maximum. The configurable session lifetime and concurrent-session limit apply to newly opened SSH sessions. Web sessions use the configured inactivity interval. Listener addresses, data location, HTTPS certificates, and cookie transport are startup flags; change them by restarting the process. Use `./bin/git-proxy -help` for flags.

Only forward an agent to a proxy you trust. The proxy uses your forwarded agent to sign authentication challenges and does not receive private key material, but a compromised proxy can use that agent while connected. Users can configure upstream destinations reachable by the proxy; deploy it on a network appropriate for those trusted users and constrain egress at the network boundary when required.

## Development and verification

```sh
npm ci
npm run build
go test ./...
go build ./cmd/git-proxy
```

The Go integration test starts a controlled upstream SSH fixture and runs real Git push, clone, pull, `ls-remote`, and remote archive through a forwarded agent. It checks unknown-key denial, command restrictions, missing-agent denial, SFTP/port-forward denial, host-key mismatch, read-only routes, streamed activity, and a real terminal session. Store tests cover account isolation, key-specific precedence, revocation, concurrent bootstrap, concurrent last-administrator changes, password revisions, persistence, and validation. Web tests cover authentication and authorization boundaries.
