export interface Device {
  network: string;
  root_public_key: string;
  trust_checkpoint: {
    observed_at: string | null;
    crl_sequence: number | null;
    key_sequence: number | null;
  };
  authority: string | null;
  local_authority_available: boolean;
  authority_configured: boolean;
  node_public_key: string;
  certificate_id: string | null;
  certificate_expires_at: string | null;
  peer_node: string | null;
  ticket: string | null;
  received_messages: number;
  ready: boolean;
  enrollment_pending: boolean;
  problem: string | null;
  authority_via_bridge: boolean;
  bridge_host_node: string | null;
  bridge_ticket: string | null;
  sharing_host: boolean;
  sharing_enabled: boolean;
  sharing_config: {
    collection_id: string;
    directory: string;
    policy_id: string;
    attestation_id: string;
  } | null;
}
export interface Status {
  supported: boolean;
  device: Device | null;
  problem: string | null;
}
