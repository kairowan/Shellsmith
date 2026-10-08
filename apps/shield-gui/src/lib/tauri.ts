import { Channel, invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";

export type SignConfig = {
  keystore_path?: string | null;
  key_alias?: string | null;
  auto_sign_enabled: boolean;
  ks_type?: string | null;
  sign_v1: boolean;
  sign_v2: boolean;
  sign_v3: boolean;
  sign_v4: boolean;
};

export type ThemeMode = "system" | "light" | "dark";

export type AppConfig = {
  locale: "zh" | "en" | string;
  theme_mode: ThemeMode | string;
  telemetry_enabled: boolean;
  protect_defaults?: ProtectDefaults;
};

export type ProtectDefaults = {
  runtime_mode: "standard" | "android_api19";
  environment_policy: "compatible" | "strict";
  protection_profile: "compat" | "balanced" | "strict";
  ai_resistance: "off" | "balanced" | "high";
  xop_pvm2_packer_path: string;
  xop_true_vmp_prefixes: string[];
  sign_after_protect: boolean | null;
  certificate_id: string | null;
  output_directory_mode: "source" | "fixed";
  fixed_output_directory: string;
};

export type CertificateRecord = {
  id: string;
  name: string;
  source_type: "managed" | "external" | string;
  keystore_path: string;
  keystore_password: string;
  key_alias: string;
  key_password: string;
  ks_type: "JKS" | "PKCS12" | string;
  sign_v1: boolean;
  sign_v2: boolean;
  sign_v3: boolean;
  sign_v4: boolean;
  auto_sign_enabled: boolean;
  note: string;
  is_default: boolean;
  created_at: number;
  updated_at: number;
  last_verified_at?: number | null;
  last_verify_status: "unknown" | "success" | "failed" | string;
  last_verify_message?: string | null;
};

export type CertificateUpsertInput = {
  id?: string | null;
  name: string;
  source_type: "managed" | "external" | string;
  keystore_path: string;
  keystore_password: string;
  key_alias: string;
  key_password: string;
  ks_type?: "JKS" | "PKCS12" | string | null;
  sign_v1: boolean;
  sign_v2: boolean;
  sign_v3: boolean;
  sign_v4: boolean;
  auto_sign_enabled: boolean;
  note: string;
  set_as_default: boolean;
  copy_keystore_to_managed: boolean;
  managed_file_name?: string | null;
};

export type CertificateValidationInput = {
  keystore_path: string;
  keystore_password: string;
  key_alias: string;
  ks_type?: "JKS" | "PKCS12" | string | null;
};

export type CertificateValidationResult = {
  valid: boolean;
  aliases: string[];
  resolved_alias?: string | null;
  message?: string | null;
};

export type CreateManagedCertificateInput = {
  name: string;
  file_name: string;
  key_alias: string;
  keystore_password: string;
  key_password: string;
  ks_type?: "JKS" | "PKCS12" | string | null;
  sign_v1: boolean;
  sign_v2: boolean;
  sign_v3: boolean;
  sign_v4: boolean;
  auto_sign_enabled: boolean;
  note: string;
  set_as_default: boolean;
  dname: string;
  validity_days: number;
  key_size: number;
};

export type ApkCheckResult = {
  verdict: "ready" | "warning" | "blocked";
  checks: ApkPreflightCheck[];
  facts: ApkPreflightFacts;
  error_code?: "inspection_failed" | "certificate_unreadable" | string | null;
  error?: string | null;
};

export type ApkPreflightCheck = {
  code: string;
  severity: "ready" | "warning" | "blocked";
  detail?: string | null;
};

export type ApkPreflightFacts = {
  apk_size: number;
  dex_count: number;
  dex_total_size: number;
  native_library_count: number;
  compressed_native_library_count: number;
  native_abis: string[];
  min_sdk?: number | null;
  target_sdk?: number | null;
  extract_native_libs?: boolean | null;
  split_name?: string | null;
  uses_http_legacy?: boolean;
};

export type CertCompareResult = {
  matches: boolean;
  apk_fingerprint?: string | null;
  ks_fingerprint?: string | null;
  error?: string | null;
};

export type UpdateCheckResult = {
  has_update: boolean;
  latest_version?: string | null;
  release_url?: string | null;
  update_level?: "patch" | "minor" | "major" | string | null;
  notes?: string | null;
  can_install: boolean;
};

export type UpdateProgress = {
  phase: "checking" | "downloading" | "verifying" | "installing";
  downloaded: number;
  total: number | null;
};

export type AppInfo = {
  version: string;
  git_hash: string;
  build_date: string;
};

export type BuildInfo = {
  apktool_version: string;
  apksigner_version: string;
  java_version: string;
  java_ready: boolean;
  keytool_ready: boolean;
  java_major?: number | null;
  min_java_major: number;
  xop_pvm2_packer_bundled: boolean;
  xop_pvm2_min_java_major: number;
  bundletool_bundled: boolean;
  aapt2_bundled: boolean;
};

export type AabInspection = {
  path: string;
  has_base: boolean;
  has_bundle_config: boolean;
  modules: string[];
  dynamic_feature_modules: string[];
  dex_entries: number;
  manifest_entries: number;
  module_processing: string;
  protection_status: string;
  bundletool: "validated" | string;
  application_id?: string | null;
};

export type AabProtectRequest = {
  taskId: string;
  input: string;
  output: string;
  apksOutput?: string | null;
  certificateId: string;
  runtimeCertSha256?: string | null;
  allowUploadCertBinding: boolean;
  playDeliveryAdapter: boolean;
  environmentPolicy: "compatible" | "strict";
  protectionProfile: "compat" | "balanced" | "strict";
  aiResistance: "off" | "balanced" | "high";
  xopTrueVmpPrefixes: string[];
};

export type TaskKind = "protect" | "ios_protect" | "sign" | "update";
export type TaskStatus = "running" | "succeeded" | "failed" | "cancelled";

export type TaskLog = {
  timestamp_ms: number;
  step: string;
  level: "info" | "error";
  message: string;
};

export type TaskSnapshot = {
  task_id: string;
  kind: TaskKind;
  status: TaskStatus;
  current_step: string;
  input_path: string;
  output_path: string;
  started_at_ms: number;
  finished_at_ms?: number | null;
  logs: TaskLog[];
  error?: string | null;
};

export type DragDropPayload = {
  paths?: string[];
};

export type IosCheckSeverity = "ready" | "warning" | "blocked";

export type IosCheck = {
  code: string;
  severity: IosCheckSeverity;
  message: string;
  reference?: string | null;
};

export type IosTargetInspection = {
  name: string;
  product_type: string;
  bundle_id?: string | null;
  team_id?: string | null;
  deployment_target?: string | null;
  project_file?: string | null;
  build_library_for_distribution: boolean;
};

export type IosProjectInspection = {
  project_path: string;
  source_root: string;
  kind: "project" | "workspace" | string;
  requested_scheme?: string | null;
  schemes: string[];
  targets: IosTargetInspection[];
  xcode: {
    available: boolean;
    version?: string | null;
    developer_dir?: string | null;
    diagnostic?: string | null;
  };
  checks: IosCheck[];
};

export type IosProtectionReport = {
  schema_version: number;
  profile: "compat" | "balanced" | "strict";
  inspection: IosProjectInspection;
  output_project?: string | null;
  archive?: string | null;
  ipa?: string | null;
  archive_verification?: {
    app_path: string;
    bundle_id?: string | null;
    executable?: string | null;
    talsec_framework_present: boolean;
    privacy_manifest_present: boolean;
    talsec_dsym_matches?: boolean | null;
    selected_literal_count: number;
    checks: IosCheck[];
  } | null;
  checks: IosCheck[];
};

export type IosSdkStatus = {
  version: string;
  path: string;
  ready: boolean;
  diagnostic: string | null;
};

export type IosProtectRequest = {
  taskId: string;
  project: string;
  scheme: string;
  configuration: string;
  teamId: string;
  bundleIds: string[];
  entrypoint?: string | null;
  output: string;
  profile: "compat" | "balanced" | "strict";
  confidentialConfig?: string | null;
  watcherMail?: string | null;
  isProd: boolean;
  appAttestEndpoint?: string | null;
  exportOptions?: string | null;
  exportMethod: string;
  allowProvisioningUpdates: boolean;
  dryRun: boolean;
};

export type { SharingChoice, SharingInspection } from "./application-sharing-state";
import type { SharingChoice, SharingInspection } from "./application-sharing-state";

export const api = {
  inspectApplicationSharing: (path: string) => invoke<SharingInspection | null>("inspect_application_sharing", { path }),
  releaseApplicationInspection: (inspectionId: string) => invoke<void>("release_application_inspection", { inspectionId }),
  saveApplicationSharing: (inspectionId: string, enabled: boolean) => invoke<void>("save_application_sharing", { inspectionId, enabled }),
  checkApk: (path: string, runtimeMode: "standard" | "android_api19", certificateId?: string | null) =>
    invoke<ApkCheckResult>("check_apk", { path, runtimeMode, certificateId: certificateId ?? null }),
  checkAab: (path: string) => invoke<AabInspection>("check_aab", { path }),
  protectAab: (request: AabProtectRequest) => invoke<void>("protect_aab", { request }),
  protectApk: (taskId: string, input: string, output: string, runtimeMode: "standard" | "android_api19", environmentPolicy: "compatible" | "strict", protectionProfile: "compat" | "balanced" | "strict", aiResistance: "off" | "balanced" | "high", xopPvm2PackerPath: string | null, xopTrueVmpPrefixes: string[], signedOutput?: string | null, certificateId?: string | null, excludedAbis: string[] = [], sharing: SharingChoice | null = null) =>
    invoke<void>("protect_apk", {
      request: {
        taskId,
        sharing,
        input,
        output,
        signedOutput: signedOutput ?? null,
        apktoolPath: null,
        runtimeMode,
        environmentPolicy,
        protectionProfile,
        aiResistance,
        xopPvm2PackerPath,
        xopTrueVmpPrefixes,
        excludedAbis,
        certificateId: certificateId ?? null,
      },
    }),
  checkIosProject: (project: string, scheme?: string | null) =>
    invoke<IosProjectInspection>("check_ios_project", { project, scheme: scheme || null }),
  protectIosProject: (request: IosProtectRequest) =>
    invoke<IosProtectionReport>("protect_ios_project", { request }),
  cancelIosProtect: () => invoke<void>("cancel_ios_protect"),
  iosSdkStatus: () => invoke<IosSdkStatus>("ios_sdk_status"),
  prepareIosSdk: (taskId: string, importZip: string | null) =>
    invoke<IosSdkStatus>("prepare_ios_sdk", { taskId, importZip }),
  cancelProtect: () => invoke<void>("cancel_protect"),
  checkFileExists: (path: string) => invoke<boolean>("check_file_exists", { path }),
  showInFolder: (path: string) => invoke<void>("show_in_folder", { path }),
  deleteFile: (path: string) => invoke<void>("delete_file", { path }),
  getAppConfig: () => invoke<AppConfig>("get_app_config"),
  saveAppConfig: (config: AppConfig) => invoke<void>("save_app_config", { config }),
  saveProtectDefaults: (defaults: ProtectDefaults) => invoke<void>("save_protect_defaults", { defaults }),
  listCertificates: () => invoke<CertificateRecord[]>("list_certificates"),
  saveCertificate: (input: CertificateUpsertInput) =>
    invoke<CertificateRecord>("save_certificate", { input }),
  validateCertificate: (input: CertificateValidationInput) =>
    invoke<CertificateValidationResult>("validate_certificate", { input }),
  setDefaultCertificate: (id: string) =>
    invoke<void>("set_default_certificate", { id }),
  deleteCertificate: (id: string, removeKeystoreFile: boolean) =>
    invoke<CertificateRecord[]>("delete_certificate", { id, removeKeystoreFile }),
  verifyCertificate: (id: string) =>
    invoke<CertificateRecord>("verify_certificate", { id }),
  createManagedCertificate: (input: CreateManagedCertificateInput) =>
    invoke<CertificateRecord>("create_managed_certificate_command", { input }),
	  signApk: (args: {
	    taskId: string;
	    apkPath: string;
	    outputPath?: string | null;
	    apksignerPath?: string | null;
	    certificateId: string;
	    sharing?: SharingChoice | null;
	  }) => invoke<void>("sign_apk", { request: args }),
  getLatestTask: (kind: TaskKind) => invoke<TaskSnapshot | null>("get_latest_task", { kind }),
  listKeystoreAliases: (keystorePath: string, ksPass: string, ksType: string) =>
    invoke<string[]>("list_keystore_aliases", { keystorePath, ksPass, ksType }),
	  compareCertFingerprints: (args: {
	    apkPath: string;
	    certificateId: string;
	  }) => invoke<CertCompareResult>("compare_cert_fingerprints", args),
  checkUpdate: () => invoke<UpdateCheckResult>("check_update"),
  installUpdate: (version: string, onProgress: (progress: UpdateProgress) => void) => {
    const channel = new Channel<UpdateProgress>();
    channel.onmessage = onProgress;
    return invoke<void>("install_update", { version, onProgress: channel });
  },
  syncTelemetry: () => invoke<void>("sync_telemetry"),
  openUrl: (url: string) => invoke<void>("open_url", { url }),
  dismissUpdate: (version: string) => invoke<void>("dismiss_update", { version }),
  getDismissedVersion: () => invoke<string | null>("get_dismissed_version"),
  getAppInfo: () => invoke<AppInfo>("get_app_info"),
  getBuildInfo: () => invoke<BuildInfo>("get_build_info"),
  getDiagnosticInfo: () => invoke<string>("get_diagnostic_info"),
};

export async function openFileDialog(
  filterName: string,
  extensions: string[],
  defaultPath?: string,
) {
  const result = await open({
    multiple: false,
    defaultPath,
    filters: [{ name: filterName, extensions }],
  });
  if (Array.isArray(result)) {
    return result[0] ?? null;
  }
  return result ?? null;
}

export async function openDirectoryDialog(defaultPath?: string) {
  const result = await open({ directory: true, multiple: false, defaultPath });
  if (Array.isArray(result)) return result[0] ?? null;
  return result ?? null;
}

export function onTauriEvent<T>(event: string, handler: (payload: T) => void) {
  return listen<T>(event, (e) => handler(e.payload));
}

export type { UnlistenFn };
