import { invoke } from "@tauri-apps/api/core";

export interface ClaudeScienceStatus {
  supported: boolean;
  installed: boolean;
  exe?: string | null;
  version?: string | null;
  profileDir?: string | null;
  hasVirtualLogin: boolean;
  message: string;
}

export interface ClaudeScienceLaunchReport {
  pid: number;
  port: number;
  sandboxPort: number;
  dataDir: string;
  baseUrl: string;
  linked: string[];
}

export const claudeScienceApi = {
  async getStatus(): Promise<ClaudeScienceStatus> {
    return await invoke("claude_science_status");
  },

  async launch(): Promise<ClaudeScienceLaunchReport> {
    return await invoke("claude_science_launch");
  },

  async stop(): Promise<string> {
    return await invoke("claude_science_stop");
  },
};
