export type ProcessArchitecture = "native_arm64" | "emulated_x64" | "emulated_x86" | "could_not_verify";
export type AppArchitecture = "native_arm64" | "emulated" | "mixed" | "could_not_verify";
export type FileArchitecture = "arm64" | "x64" | "x86";
export type VerificationIssue =
  | "access_denied" | "process_unavailable" | "hybrid_executable"
  | "conflicting_evidence" | "file_unverified" | "runtime_unverified";
export type Evidence =
  | { kind: "pe_header"; machine: number }
  | { kind: "is_wow64_process2"; process_machine: number; native_machine: number }
  | { kind: "process_machine_type"; machine: number; machine_attributes: number }
  | { kind: "win32_error"; operation: string; code: number }
  | { kind: "explanation"; message: string };

export interface Process {
  pid: number;
  name: string;
  image_path: string | null;
  classification: {
    architecture: ProcessArchitecture;
    verification_issue: VerificationIssue | null;
    image_file_architecture: FileArchitecture | null;
    evidence: Evidence[];
  };
  cpu_percent: number | null;
  working_set_bytes: number | null;
}

export interface DesktopScan {
  apps: RunningApp[];
  desktop_scope_available: boolean;
}

export interface RunningApp {
  name: string;
  desktop_app: boolean;
  architecture: AppArchitecture;
  grouping: { kind: "executable_path"; path: string }
    | { kind: "product_version"; directory: string; product: string; company: string }
    | null;
  processes: Process[];
  cpu_percent: number | null;
  working_set_bytes: number | null;
  icon: string | null;
}

export interface CheckedFile {
  name: string;
  finding: { Ok: { architecture: "arm64" | "x64" | "x86" | "could_not_verify"; evidence: Evidence[] } }
    | { Err: string };
}

export const processLabels: Record<ProcessArchitecture, string> = {
  native_arm64: "Native (ARM64)",
  emulated_x64: "Emulated (x64)",
  emulated_x86: "Emulated (x86)",
  could_not_verify: "Couldn’t verify",
};

export function appLabel(app: RunningApp): string {
  if (app.architecture === "mixed") return "Mixed";
  if (app.architecture !== "emulated") return processLabels[app.architecture];
  const first = app.processes[0]?.classification.architecture;
  return first && app.processes.every((process) => process.classification.architecture === first)
    ? processLabels[first]
    : "Emulated";
}

export function appKey(app: RunningApp): string {
  const group = app.grouping;
  if (group?.kind === "executable_path") return group.path;
  if (group?.kind === "product_version") return JSON.stringify([group.directory, group.company, group.product]);
  return JSON.stringify([app.name, app.processes[0]?.pid]);
}

export function summary(apps: RunningApp[], desktopScope: boolean): string {
  const emulated = apps.filter((app) => app.architecture === "mixed" || app.architecture === "emulated").length;
  const unknown = apps.filter((app) => app.architecture === "could_not_verify").length;
  const subject = desktopScope ? "desktop" : "running";
  if (emulated === 1) return `1 ${subject} app uses emulation`;
  if (emulated > 1) return `${emulated} ${subject} apps use emulation`;
  if (apps.length === 0) return `No ${subject} apps found`;
  return unknown === 0 ? `All ${subject} apps are native` : "No emulated apps verified";
}

const hex = (code: number, digits = 4) => `0x${code.toString(16).toUpperCase().padStart(digits, "0")}`;

export function evidenceText(evidence: Evidence): string {
  switch (evidence.kind) {
    case "pe_header": return `PE header machine ${hex(evidence.machine)}`;
    case "is_wow64_process2": return `IsWow64Process2: process ${hex(evidence.process_machine)}, host ${hex(evidence.native_machine)}`;
    case "process_machine_type": return `Process machine ${hex(evidence.machine)}, attributes ${hex(evidence.machine_attributes, 8)}`;
    case "win32_error": return `${evidence.operation}: Win32 error ${evidence.code}`;
    case "explanation": return evidence.message;
  }
}

export const issueLabels: Record<VerificationIssue, string> = {
  access_denied: "Access denied",
  process_unavailable: "Process unavailable",
  hybrid_executable: "Hybrid executable",
  conflicting_evidence: "Conflicting evidence",
  file_unverified: "File couldn’t be verified",
  runtime_unverified: "Runtime couldn’t be verified",
};

export const issueDescriptions: Record<VerificationIssue, string> = {
  access_denied: "Windows denied access to the process.",
  process_unavailable: "Windows couldn’t open the process.",
  hybrid_executable: "ArmCheck found ARM64EC or ARM64X hybrid evidence.",
  conflicting_evidence: "The architecture checks disagreed.",
  file_unverified: "ArmCheck couldn’t verify the executable file.",
  runtime_unverified: "Windows didn’t provide enough runtime information.",
};

export const fileArchitectureLabels = { arm64: "ARM64", x64: "x64", x86: "x86" };

export function verificationIssues(app: RunningApp): VerificationIssue[] {
  if (app.architecture !== "could_not_verify") return [];
  const issues = new Set<VerificationIssue>();
  for (const { classification } of app.processes) {
    if (classification.verification_issue !== null) issues.add(classification.verification_issue);
  }
  return [...issues];
}

export function verificationCounts(apps: RunningApp[]): Map<VerificationIssue, number> {
  const counts = new Map<VerificationIssue, number>();
  for (const app of apps) {
    for (const issue of verificationIssues(app)) counts.set(issue, (counts.get(issue) ?? 0) + 1);
  }
  return counts;
}
