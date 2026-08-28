import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Embedded policy-based access control (PBAC), deny-by-default.
 *
 * OPA's Go SDK is unavailable to TypeScript services, so this module
 * evaluates a small, deliberately rego-independent JSON policy format that
 * any platform service can implement. Policy files live under POLICY_DIR as
 * `*.policy.json` documents shaped:
 *
 * ```json
 * {
 *   "version": "1.0",
 *   "policies": [
 *     {
 *       "name": "nimasa-approver-issues-credentials",
 *       "roles": ["nimasa-approver"],
 *       "clearance": ["*"],
 *       "tenant": "*",
 *       "resource": "credential",
 *       "action": "issue",
 *       "classification": ["CONFIDENTIAL"]
 *     }
 *   ]
 * }
 * ```
 *
 * Every entry is an ALLOW rule; anything not matched is DENIED. The engine
 * loads fail-closed at startup: a missing directory, an unreadable or
 * malformed file, a schema violation, or a directory without at least one
 * rule aborts boot. There is no empty-policy "allow all" degradation.
 */

export const POLICY_DIR_ENV = "POLICY_DIR";
export const POLICY_VERSION = "1.0";
export const MAX_POLICY_FILE_BYTES = 1 << 20;
export const MAX_RULES_TOTAL = 1024;

export const CLASSIFICATIONS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "FIDUCIARY_SEGREGATED"] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];

const IDENTIFIER_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface PolicyRule {
  /** Stable rule name used in decisions and audit logs. */
  name: string;
  /** Principal roles the rule applies to; "*" matches any authenticated role. */
  roles: string[];
  /** Clearance labels admitted; "*" or absence matches any/no clearance claim. */
  clearance?: string[];
  /** Tenant identifier admitted; "*" or absence matches any tenant. */
  tenant?: string;
  /** Resource identifier (for example "credential", "wallet", "status-list"). */
  resource: string;
  /** Action identifier (for example "issue", "revoke", "verify", "read"). */
  action: string;
  /** Data classifications admitted; "*" or absence matches any classification. */
  classification?: string[];
}

export interface PolicyRequest {
  roles: ReadonlySet<string>;
  clearance?: string | undefined;
  tenant?: string | undefined;
  resource: string;
  action: string;
  classification?: string | undefined;
}

export interface PolicyDecision {
  allowed: boolean;
  matchedRule?: string;
}

export class PolicyEngine {
  private constructor(private readonly rules: readonly PolicyRule[]) {}

  /** Loads and strictly validates every `*.policy.json` under directory. */
  public static async load(directory: string): Promise<PolicyEngine> {
    let names: string[];
    try {
      names = await readdir(directory);
    } catch {
      throw new Error(`policy directory ${directory} is not readable (fail-closed)`);
    }
    const files = names.filter((name) => name.endsWith(".policy.json")).sort();
    if (files.length === 0) {
      throw new Error(`policy directory ${directory} contains no *.policy.json files (fail-closed)`);
    }
    const rules: PolicyRule[] = [];
    const ruleNames = new Set<string>();
    for (const file of files) {
      const path = join(directory, file);
      const raw = await readFile(path, "utf8").catch(() => {
        throw new Error(`policy file ${path} is not readable (fail-closed)`);
      });
      if (Buffer.byteLength(raw, "utf8") > MAX_POLICY_FILE_BYTES) {
        throw new Error(`policy file ${path} exceeds ${MAX_POLICY_FILE_BYTES} bytes (fail-closed)`);
      }
      let document: unknown;
      try {
        document = JSON.parse(raw) as unknown;
      } catch {
        throw new Error(`policy file ${path} is not valid JSON (fail-closed)`);
      }
      for (const rule of parsePolicyDocument(document, path)) {
        if (ruleNames.has(rule.name)) {
          throw new Error(`policy rule name ${rule.name} is duplicated (fail-closed)`);
        }
        ruleNames.add(rule.name);
        rules.push(rule);
      }
    }
    if (rules.length === 0) {
      throw new Error(`policy directory ${directory} declares no allow rules (fail-closed)`);
    }
    if (rules.length > MAX_RULES_TOTAL) {
      throw new Error(`policy directory ${directory} declares more than ${MAX_RULES_TOTAL} rules (fail-closed)`);
    }
    return new PolicyEngine(rules);
  }

  /** Fail-closed factory bound to the POLICY_DIR environment variable. */
  public static async fromEnv(env: NodeJS.ProcessEnv = process.env): Promise<PolicyEngine> {
    const directory = env[POLICY_DIR_ENV];
    if (directory === undefined || directory.trim().length === 0) {
      throw new Error(`${POLICY_DIR_ENV} is required (fail-closed)`);
    }
    return PolicyEngine.load(directory);
  }

  /** Returns allow only when at least one allow-rule matches; deny otherwise. */
  public evaluate(request: PolicyRequest): PolicyDecision {
    for (const rule of this.rules) {
      if (matches(rule, request)) {
        return { allowed: true, matchedRule: rule.name };
      }
    }
    return { allowed: false };
  }
}

function matches(rule: PolicyRule, request: PolicyRequest): boolean {
  if (!rule.roles.includes("*") && !rule.roles.some((role) => request.roles.has(role))) return false;
  if (!wildcard(rule.tenant) && rule.tenant !== request.tenant) return false;
  if (rule.tenant !== undefined && rule.tenant !== "*" && request.tenant === undefined) return false;
  if (!wildcard(rule.resource) && rule.resource !== request.resource) return false;
  if (!wildcard(rule.action) && rule.action !== request.action) return false;
  if (rule.clearance !== undefined && !rule.clearance.includes("*")) {
    if (request.clearance === undefined || !rule.clearance.includes(request.clearance)) return false;
  }
  if (rule.classification !== undefined && !rule.classification.includes("*")) {
    if (request.classification === undefined || !rule.classification.includes(request.classification)) return false;
  }
  return true;
}

function wildcard(value: string | undefined): boolean {
  return value === undefined || value === "*";
}

function parsePolicyDocument(document: unknown, path: string): PolicyRule[] {
  const fail = (detail: string): never => {
    throw new Error(`policy file ${path} is invalid: ${detail} (fail-closed)`);
  };
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    fail("document must be a JSON object");
  }
  const record = document as Record<string, unknown>;
  if (record["version"] !== POLICY_VERSION) fail(`version must be "${POLICY_VERSION}"`);
  const policies: unknown = record["policies"];
  if (!Array.isArray(policies)) return fail("policies must be an array");
  if (policies.length > MAX_RULES_TOTAL) fail(`policies must not exceed ${MAX_RULES_TOTAL} entries`);
  return (policies as unknown[]).map((entry: unknown, index: number) => parseRule(entry, `${path} rule ${index}`, fail));
}

function parseRule(entry: unknown, where: string, fail: (detail: string) => never): PolicyRule {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    fail(`${where} must be a JSON object`);
  }
  const record = entry as Record<string, unknown>;
  const allowedKeys = new Set(["name", "roles", "clearance", "tenant", "resource", "action", "classification"]);
  for (const key of Object.keys(record)) {
    if (!allowedKeys.has(key)) fail(`${where} carries unknown field ${key}`);
  }
  const name = record["name"];
  if (typeof name !== "string" || !NAME_PATTERN.test(name)) fail(`${where} name must be canonical text`);
  const roles = record["roles"];
  if (!Array.isArray(roles) || roles.length === 0 || roles.length > 32 || roles.some((role) => typeof role !== "string" || (role !== "*" && !IDENTIFIER_PATTERN.test(role as string)))) {
    fail(`${where} roles must be a non-empty array of role identifiers or "*"`);
  }
  const resource = record["resource"];
  if (typeof resource !== "string" || (resource !== "*" && !IDENTIFIER_PATTERN.test(resource))) {
    fail(`${where} resource must be an identifier or "*"`);
  }
  const action = record["action"];
  if (typeof action !== "string" || (action !== "*" && !IDENTIFIER_PATTERN.test(action))) {
    fail(`${where} action must be an identifier or "*"`);
  }
  const tenant = record["tenant"];
  if (tenant !== undefined && (typeof tenant !== "string" || tenant.length === 0 || tenant.length > 128)) {
    fail(`${where} tenant must be text or "*"`);
  }
  const clearance = parseOptionalStringList(record["clearance"], `${where} clearance`, fail);
  const classification = parseOptionalStringList(record["classification"], `${where} classification`, fail);
  if (classification !== undefined) {
    for (const label of classification) {
      if (label !== "*" && !(CLASSIFICATIONS as readonly string[]).includes(label)) {
        fail(`${where} classification ${label} is not a known classification`);
      }
    }
  }
  return {
    name,
    roles: roles as string[],
    resource,
    action,
    ...(tenant !== undefined ? { tenant } : {}),
    ...(clearance !== undefined ? { clearance } : {}),
    ...(classification !== undefined ? { classification } : {}),
  };
}

function parseOptionalStringList(value: unknown, where: string, fail: (detail: string) => never): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length === 0 || value.length > 32 || value.some((entry) => typeof entry !== "string" || (entry as string).length === 0 || (entry as string).length > 64)) {
    fail(`${where} must be a non-empty array of short strings`);
  }
  return value as string[];
}
