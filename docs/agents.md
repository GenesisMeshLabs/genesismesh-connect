# AI agents on your network

An AI agent can have its own place on your Connect network, like a device. It
gets its own key and membership, sees only the Spaces you share with it, and
you can remove it without touching anything else, even when several agents run
on one computer.

`genesismesh-connect-agent` (in `apps/agent`) holds that identity and serves it
to the agent's tools over the Model Context Protocol (MCP).

## Add an agent

1. On the device that runs your network, choose **Add device** and copy the
   invitation.
2. On the computer where the agent runs, give the agent its own profile folder
   and ask to join:

   ```text
   genesismesh-connect-agent ~/agents/research join "<invitation>" "Research agent"
   ```

   It prints a six-digit code and waits.
3. On your network device, check that the code matches, then choose
   **Allow device**. The agent is now on your network under its own name.
4. Share a folder with it like with any device: choose the folder and tick the
   agent as a recipient. Until you do, it can reach nothing.

Each profile folder is one agent. A second agent on the same computer joins
with another folder and gets its own identity.

## Connect it to an AI tool

The agent's MCP server runs over stdio. In an MCP client's configuration:

```json
{
  "mcpServers": {
    "genesis-mesh": {
      "command": "genesismesh-connect-agent",
      "args": ["/home/me/agents/research", "mcp"]
    }
  }
}
```

It offers three read-only tools:

| Tool | What it does |
| --- | --- |
| `list_shared` | Lists the Spaces shared with this agent and who shares them. |
| `browse` | Lists files and folders in one shared Space. |
| `read_file` | Reads one file: text as text, other files as size and SHA-256. |

Every call goes through the same checks as any device: the sharing device asks
your network's authority, so the agent can read only what its Spaces allow,
until they expire. A refusal comes back to the agent as an error it can read.
`genesismesh-connect-agent <profile> status` shows the same view in a terminal.

## Remove an agent

On the device that runs your network, open **Devices** and choose **Remove
from network** on the agent. Its membership is revoked at once; its next
request is refused, and every other device and agent keeps working.

## Where its key lives

The agent's key stays in the operating system's credential store: the
Secret Service on Linux (for example GNOME Keyring), the Keychain on macOS
and DPAPI on Windows. The profile folder holds its public records only.

## Not yet

- **Approving each request:** an agent's reads are allowed by the Spaces you
  share. Approving each request on your phone, with the exact document and
  expiry, needs the phone approval that is still being qualified.
- **Writing:** agents read only; sending files or using shared services is not
  offered over MCP yet.
- **Owner's view:** an agent shows as a device named as it asked to join; the
  app does not label agents separately yet.
