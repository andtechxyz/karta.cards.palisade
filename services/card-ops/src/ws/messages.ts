/**
 * Shared WebSocket message shape for the card-ops relay.
 *
 * Mirrors the RCA provisioning relay protocol so existing mobile/admin
 * NFC APDU code can be reused without branching on service.
 *
 *   Server → Client: { type: "apdu", hex, phase?, progress? }
 *   Client → Server: { type: "response", hex, sw }
 *   Client → Server: { type: "error", code?, message? }  (client-side fault)
 *   Server → Client: { type: "complete", ...opSpecific }
 *   Server → Client: { type: "error", code, message }
 */

export interface WSMessage {
  type: 'apdu' | 'response' | 'complete' | 'error';
  hex?: string;
  sw?: string;
  phase?: string;
  progress?: number;
  code?: string;
  message?: string;
  // Op-specific payload attached to `complete` — e.g. list_applets returns
  // `applets: [{aid, lifecycle, privileges}]`.  Kept as an open record so
  // individual operations can add fields without widening this interface.
  [key: string]: unknown;
}
