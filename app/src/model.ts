export type ProcessArchitecture = "native_arm64" | "emulated_x64" | "emulated_x86" | "could_not_verify";
export type AppArchitecture = "native_arm64" | "emulated" | "mixed" | "could_not_verify";
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
  classification: { architecture: ProcessArchitecture; evidence: Evidence[] };
  cpu_percent: number | null;
  working_set_bytes: number | null;
}

export interface RunningApp {
  name: string;
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

export function summary(apps: RunningApp[]): string {
  const emulated = apps.filter((app) => app.architecture === "mixed" || app.architecture === "emulated").length;
  const unknown = apps.filter((app) => app.architecture === "could_not_verify").length;
  if (emulated === 1) return "1 running app uses emulation";
  if (emulated > 1) return `${emulated} running apps use emulation`;
  if (apps.length === 0) return "No running apps found";
  return unknown === 0 ? "All your running apps are native" : "No emulated apps verified";
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

export function unverifiedReasons(app: RunningApp): string[] {
  if (app.architecture !== "could_not_verify") return [];
  return [...new Set(app.processes.filter((process) => process.classification.architecture === "could_not_verify").map((process) => {
    const evidence = process.classification.evidence;
    const openError = evidence.find((item) => item.kind === "win32_error" && item.operation.startsWith("OpenProcess"));
    const explanations = evidence.flatMap((item) => item.kind === "explanation" ? [item.message] : []);
    if (openError?.kind === "win32_error") {
      return openError.code === 5 ? "Windows denied access." : "Windows couldn’t open this process.";
    }
    if (explanations.some((message) => /ARM64EC|ARM64X/.test(message))) return "This executable uses a hybrid ARM format.";
    if (explanations.some((message) => message.includes("disagrees with the executable"))) return "Windows and the file reported different architectures.";
    if (explanations.some((message) => message.includes("runtime architecture queries disagree"))) return "Windows returned conflicting architecture information.";
    if (explanations.some((message) => /PE|machine code/.test(message))) return "The executable’s architecture couldn’t be read reliably.";
    return "Windows didn’t return enough architecture information.";
  }))];
}
