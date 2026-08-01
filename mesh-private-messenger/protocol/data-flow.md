# Data Flow and Trust Boundaries

Whatsdown performs identity, session, ratchet, and message processing on user
devices. Services route public directory data and opaque ciphertext. The first
deployment may combine logical services into one Mesh process and one
PostgreSQL instance with separate schemas; the visibility boundaries remain.

```mermaid
flowchart LR
  subgraph Device["User Device"]
    UI["UI"]
    Core["Compiled Mesh Messenger Core"]
    Local["Local SQLite metadata and encrypted blobs"]
    Keys["OS key store adapter"]
    UI --> Core
    Core --> Local
    Core --> Keys
  end

  subgraph Edge["Privacy and Connection Edge"]
    Relay["Opaque relay"]
  end

  subgraph Services["Mesh Services"]
    Directory["Directory and Prekeys"]
    Delivery["Mailbox Delivery"]
    Stream["WebSocket Stream"]
    Outbox["Durable Outbox"]
    Push["Generic Push Broker"]
    Transparency["Key Transparency"]
    Abuse["Anonymous Abuse Gate"]
  end

  DirectoryDb[("Directory PostgreSQL")]
  DeliveryDb[("Delivery PostgreSQL")]
  TransparencyDb[("Transparency PostgreSQL")]
  Objects[("Encrypted Object Storage")]
  Witnesses["Independent Witnesses"]
  Chain["Optional Checkpoint Anchor"]

  Core -->|"opaque requests"| Relay
  Relay --> Directory
  Relay --> Delivery
  Relay --> Stream
  Relay --> Transparency
  Stream --> Delivery
  Abuse --> Directory
  Abuse --> Delivery
  Directory --> DirectoryDb
  Delivery --> DeliveryDb
  Delivery --> Outbox
  Outbox --> Push
  Core -->|"encrypted attachment chunks"| Objects
  Transparency --> TransparencyDb
  Transparency --> Witnesses
  Witnesses --> Chain
```

## Identity and prekeys

1. A device generates its account authorization, signing, DH, prekey, mailbox,
   and local-storage material locally.
2. It publishes public account/device credentials, signed and one-time prekeys,
   supported suites, expiry, and transparency evidence.
3. A sender resolves the exact username or scans a QR code, fetches a prekey
   bundle, verifies the credential and signature, and checks available
   transparency evidence.
4. The sender performs the asynchronous handshake and creates the initial
   encrypted envelope locally. Private material never enters the directory.

## Durable send and receive

```mermaid
sequenceDiagram
  participant Sender as Sender Device
  participant Edge as Privacy Edge
  participant Delivery as Mesh Delivery
  participant DB as PostgreSQL
  participant Stream as Recipient Stream
  participant Push as Push Broker
  participant Recipient as Recipient Device

  Sender->>Edge: Opaque envelope batch
  Edge->>Delivery: Forward without sender identity
  Delivery->>DB: Insert envelope and outbox event
  DB-->>Delivery: Commit
  Delivery-->>Sender: Accepted envelope IDs
  Delivery->>Stream: Wake active mailbox
  alt recipient offline
    Delivery->>Push: Generic wake token
    Push-->>Recipient: Encrypted data available
  end
  Recipient->>Delivery: Fetch after cursor
  Delivery->>DB: Read opaque envelopes
  Delivery-->>Recipient: Ciphertext batch
  Recipient->>Recipient: Authenticate, decrypt, and deduplicate
  Recipient->>Delivery: Acknowledge envelope IDs
  Delivery->>DB: Mark acknowledged or schedule deletion
```

The envelope and outbox event commit together. Delivery is at least once until
expiry, insertion is idempotent by mailbox and envelope ID, and retrieval is
cursor based. Exactly-once delivery is not claimed. Duplicate display is
prevented on the device using envelope ID, encrypted client message ID, sender
device ID, and conversation-local ordering data.

## Component visibility

| Component | May observe |
|---|---|
| Connection edge | Source IP and connection timing |
| Delivery core | Opaque mailbox token, ciphertext, size, and expiry |
| Directory | Username and public device set |
| Push broker | Wake token and provider token |
| Object store | Random object ID, encrypted bytes, approximate size, timing, and expiry |
| Transparency service and witnesses | Public commitments, proofs, and checkpoints |

Application payloads are canonical binary. WebSocket events carry mailbox
authentication, cursors, acknowledgements, wakeups, rate-limit status, and
shutdown notices; they never carry plaintext or server-interpreted message
types.
