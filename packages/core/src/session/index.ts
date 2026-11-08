export interface SessionRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface SessionResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** Common surface for Tier 1 (HTTP) and Tier 2 (browser). */
export interface Session {
  readonly tier: 1 | 2;
  login(): Promise<void>;
  request(req: SessionRequest): Promise<SessionResponse>;
  dispose(): Promise<void>;
}

export { BrowserSession } from "./browserSession.js";
export { HttpSession } from "./httpSession.js";
