import { ServiceError } from "../service/credential-service.js";
import {
  ROLE_AUDITOR,
  ROLE_MASTER,
  ROLE_NIMASA_INSPECTOR,
  ROLE_NIMASA_LABOUR_OFFICER,
  ROLE_OPERATOR,
  ROLE_SEAFARER,
  type AuthenticatedPrincipal,
} from "../auth/keycloak.js";
import { assertObject, assertString, route, type MetricsRegistry, type Route, type RouteRequest } from "../http/server.js";
import {
  COMPLAINT_CATEGORIES,
  COMPLAINT_CHANNELS,
  COMPLAINT_STATUSES,
  PROVIDER_KINDS,
  REFERRAL_STATUSES,
  isMember,
  sha256Hex,
  type ComplaintStatus,
} from "./types.js";
import type { RestHourPeriod } from "./rest-rules.js";
import type { ComplaintSubmitInput, Principal, WelfareService } from "./service.js";

/**
 * Crew Welfare / MLC HTTP routes (phase 8). Every route is authenticated,
 * role-gated and PBAC-evaluated with CONFIDENTIAL classification; the
 * credential routes are untouched. Mutation endpoints are idempotent under
 * the Idempotency-Key header (fail-closed when absent).
 */

const READ_ROLES = [ROLE_SEAFARER, ROLE_OPERATOR, ROLE_MASTER, ROLE_NIMASA_LABOUR_OFFICER, ROLE_NIMASA_INSPECTOR, ROLE_AUDITOR] as const;
const OFFICER = [ROLE_NIMASA_LABOUR_OFFICER] as const;

/** Acting welfare role for provenance/audit: the most specific held role. */
function actingRole(principal: AuthenticatedPrincipal): Principal {
  for (const role of [ROLE_NIMASA_LABOUR_OFFICER, ROLE_OPERATOR, ROLE_MASTER, ROLE_SEAFARER] as const) {
    if (principal.roles.has(role)) return { subject: principal.subject, role };
  }
  return { subject: principal.subject, role: "auditor" };
}

function idempotencyKey(request: RouteRequest): string {
  const value = request.headers["idempotency-key"];
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.length > 256) {
    throw new ServiceError(400, "the Idempotency-Key header is required for this mutation (fail-closed)");
  }
  return value;
}

function optionalString(body: Record<string, unknown>, field: string): string | undefined {
  const value = body[field];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) {
    throw new ServiceError(400, `${field} must be canonical non-empty text when present`);
  }
  return value;
}

export function welfareRoutes(service: WelfareService, metrics: MetricsRegistry): Record<string, Route> {
  return {
    // ---------------------------------------------------------- W1 directory
    "GET /v1/welfare/providers": route(/^\/v1\/welfare\/providers$/, [], READ_ROLES, { resource: "welfare-directory", action: "read", classification: "CONFIDENTIAL" }, async (request) => {
      const portCode = request.query["port_code"];
      if (portCode !== undefined && !/^[A-Z0-9]{2,8}$/.test(portCode)) {
        throw new ServiceError(400, "port_code must be a UN/LOCODE-style code (2-8 uppercase alphanumerics)");
      }
      const result = await service.listProviders(portCode);
      return { status: 200, body: result };
    }),
    "GET /v1/welfare/providers/{id}": route(/^\/v1\/welfare\/providers\/([A-Za-z0-9._:-]{1,128})$/, ["id"], READ_ROLES, { resource: "welfare-directory", action: "read", classification: "CONFIDENTIAL" }, async (request) => {
      return { status: 200, body: await service.getProvider(request.params["id"] ?? "") };
    }),
    "POST /v1/welfare/providers": route(/^\/v1\/welfare\/providers$/, [], OFFICER, { resource: "welfare-directory", action: "curate", classification: "CONFIDENTIAL" }, async (request) => {
      const body = assertObject(request.body);
      const principal = actingRole(assertWelfarePrincipal(request));
      const kind = assertString(body, "kind");
      if (!isMember(PROVIDER_KINDS, kind)) throw new ServiceError(400, "kind must be a documented provider kind");
      const servicesValue = body["services"] ?? [];
      if (!Array.isArray(servicesValue) || servicesValue.length > 32) throw new ServiceError(400, "services must be an array of at most 32 entries");
      const services = servicesValue.map((entry, index) => {
        const service = assertObject(entry);
        const languages = service["languages"] ?? [];
        if (!Array.isArray(languages) || languages.some((language) => typeof language !== "string")) {
          throw new ServiceError(400, `services[${index}].languages must be an array of text`);
        }
        return {
          description: assertString(service, "description"),
          eligibility: typeof service["eligibility"] === "string" ? service["eligibility"] : "",
          languages: languages as string[],
        };
      });
      const contact = body["contact"] ?? {};
      if (typeof contact !== "object" || contact === null || Array.isArray(contact)) throw new ServiceError(400, "contact must be an object");
      const created = await service.curateProvider({
        name: assertString(body, "name"),
        kind,
        portCode: assertString(body, "portCode"),
        address: typeof body["address"] === "string" ? body["address"] : "",
        contact: contact as Record<string, unknown>,
        hours: typeof body["hours"] === "string" ? body["hours"] : "",
        sourceReference: assertString(body, "sourceReference"),
      }, services, principal);
      metrics.increment("welfare_providers_registered", { port_code: created.portCode });
      return { status: 201, body: created };
    }),

    // --------------------------------------------------------- W2 complaints
    "POST /v1/welfare/complaints": route(/^\/v1\/welfare\/complaints$/, [], [ROLE_SEAFARER], { resource: "complaint", action: "submit", classification: "CONFIDENTIAL" }, async (request) => {
      const body = assertObject(request.body);
      const principal = actingRole(assertWelfarePrincipal(request));
      const channel = assertString(body, "channel");
      if (!isMember(COMPLAINT_CHANNELS, channel)) throw new ServiceError(400, "channel must be onboard_r515 (Reg 5.1.5) or flagstate_r522 (Reg 5.2.2)");
      const category = assertString(body, "category");
      if (!isMember(COMPLAINT_CATEGORIES, category)) throw new ServiceError(400, "category must be a documented MLC category");
      const attachmentsValue = body["attachments"] ?? [];
      if (!Array.isArray(attachmentsValue)) throw new ServiceError(400, "attachments must be an array of {name, sha256} descriptors");
      const operatorRef = optionalString(body, "operatorRef");
      const input: ComplaintSubmitInput = {
        channel,
        category,
        vesselRef: assertString(body, "vesselRef"),
        ...(operatorRef !== undefined ? { operatorRef } : {}),
        narrative: assertString(body, "narrative"),
        attachments: attachmentsValue as Array<{ name: string; sha256: string }>,
        rightToRedressNoticeAck: body["rightToRedressNoticeAck"] === true,
      };
      const result = await service.submitComplaint(input, idempotencyKey(request), principal);
      if (result.created) {
        metrics.increment("welfare_complaints_total", { channel: input.channel, category: input.category });
      }
      return { status: result.created ? 201 : 200, body: result };
    }),
    "GET /v1/welfare/complaints/mine": route(/^\/v1\/welfare\/complaints\/mine$/, [], [ROLE_SEAFARER], { resource: "complaint", action: "read-own", classification: "CONFIDENTIAL" }, async (request) => {
      const principal = assertWelfarePrincipal(request);
      return { status: 200, body: await service.myComplaints(principal.subject) };
    }),
    "GET /v1/welfare/complaints": route(/^\/v1\/welfare\/complaints$/, [], OFFICER, { resource: "complaint", action: "caseload", classification: "CONFIDENTIAL" }, async (request) => {
      const status = request.query["status"];
      if (status !== undefined && !isMember(COMPLAINT_STATUSES, status)) throw new ServiceError(400, "status must be a complaint status");
      const vesselRef = request.query["vessel_ref"];
      const result = await service.caseload({
        ...(status !== undefined ? { status: status as ComplaintStatus } : {}),
        ...(vesselRef !== undefined ? { vesselRef } : {}),
      });
      for (const breach of result.newlyObservedBreaches) {
        metrics.increment("welfare_complaint_sla_breaches_total", { stage: breach.stage });
      }
      return { status: 200, body: { complaints: result.complaints } };
    }),
    // Maker: submit a governed status transition (PENDING maker/checker request).
    "POST /v1/welfare/complaints/{id}/transition": route(/^\/v1\/welfare\/complaints\/([A-Za-z0-9._:-]{1,128})\/transition$/, ["id"], OFFICER, { resource: "complaint", action: "transition", classification: "CONFIDENTIAL" }, async (request) => {
      const body = assertObject(request.body);
      const principal = actingRole(assertWelfarePrincipal(request));
      const to = assertString(body, "to");
      if (!isMember(COMPLAINT_STATUSES, to)) throw new ServiceError(400, "to must be a complaint status");
      const note = optionalString(body, "note");
      const result = await service.requestTransition(request.params["id"] ?? "", {
        to,
        reasonCode: assertString(body, "reasonCode"),
        ...(note !== undefined ? { note } : {}),
      }, principal);
      return { status: 202, body: result };
    }),
    // Maker: governed identity disclosure (Reg 5.1.5(2) anti-victimization).
    "POST /v1/welfare/complaints/{id}/disclose": route(/^\/v1\/welfare\/complaints\/([A-Za-z0-9._:-]{1,128})\/disclose$/, ["id"], OFFICER, { resource: "complaint", action: "disclose", classification: "CONFIDENTIAL" }, async (request) => {
      const body = assertObject(request.body);
      const principal = actingRole(assertWelfarePrincipal(request));
      const note = optionalString(body, "note");
      const result = await service.requestDisclosure(request.params["id"] ?? "", {
        reasonCode: assertString(body, "reasonCode"),
        ...(note !== undefined ? { note } : {}),
      }, principal);
      return { status: 202, body: result };
    }),
    // Checker: a second, distinct officer approves either request kind.
    "POST /v1/welfare/complaint-transitions/{requestId}/approve": route(/^\/v1\/welfare\/complaint-transitions\/([A-Za-z0-9._:-]{1,128})\/approve$/, ["requestId"], OFFICER, { resource: "complaint", action: "transition", classification: "CONFIDENTIAL" }, async (request) => {
      const principal = actingRole(assertWelfarePrincipal(request));
      const result = await service.approveTransitionRequest(request.params["requestId"] ?? "", principal);
      if (result.kind === "disclosure") {
        metrics.increment("welfare_complaint_disclosures_total", {});
      }
      for (const stage of result.newlyObservedBreaches) {
        metrics.increment("welfare_complaint_sla_breaches_total", { stage });
      }
      return { status: 200, body: result };
    }),

    // ---------------------------------------------------------- W4 referrals
    "POST /v1/welfare/referrals": route(/^\/v1\/welfare\/referrals$/, [], [ROLE_SEAFARER, ROLE_NIMASA_LABOUR_OFFICER], { resource: "referral", action: "create", classification: "CONFIDENTIAL" }, async (request) => {
      const body = assertObject(request.body);
      const principal = actingRole(assertWelfarePrincipal(request));
      const complaintId = optionalString(body, "complaintId");
      const seafarerRef = optionalString(body, "seafarerRef");
      const result = await service.createReferral({
        serviceId: assertString(body, "serviceId"),
        consentAt: assertString(body, "consentAt"),
        ...(complaintId !== undefined ? { complaintId } : {}),
        ...(seafarerRef !== undefined ? { seafarerRef } : {}),
      }, idempotencyKey(request), principal);
      return { status: result.created ? 201 : 200, body: result };
    }),
    "GET /v1/welfare/referrals/mine": route(/^\/v1\/welfare\/referrals\/mine$/, [], [ROLE_SEAFARER], { resource: "referral", action: "read-own", classification: "CONFIDENTIAL" }, async (request) => {
      const principal = assertWelfarePrincipal(request);
      return { status: 200, body: await service.myReferrals(principal.subject) };
    }),
    "POST /v1/welfare/referrals/{id}/transition": route(/^\/v1\/welfare\/referrals\/([A-Za-z0-9._:-]{1,128})\/transition$/, ["id"], OFFICER, { resource: "referral", action: "transition", classification: "CONFIDENTIAL" }, async (request) => {
      const body = assertObject(request.body);
      const principal = actingRole(assertWelfarePrincipal(request));
      const to = assertString(body, "to");
      if (!isMember(REFERRAL_STATUSES, to)) throw new ServiceError(400, "to must be a referral status");
      const outcomeNote = optionalString(body, "outcomeNote");
      const result = await service.transitionReferral(request.params["id"] ?? "", {
        to,
        ...(outcomeNote !== undefined ? { outcomeNote } : {}),
      }, principal);
      return { status: 200, body: result };
    }),

    // -------------------------------------------------- W3 rest-hour records
    "POST /v1/rest-hours/records": route(/^\/v1\/rest-hours\/records$/, [], [ROLE_OPERATOR, ROLE_MASTER], { resource: "rest-hours", action: "submit", classification: "CONFIDENTIAL" }, async (request) => {
      const body = assertObject(request.body);
      const principal = actingRole(assertWelfarePrincipal(request));
      const periodsValue = body["periods"];
      if (!Array.isArray(periodsValue)) throw new ServiceError(400, "periods must be an array of {start, end, kind}");
      const result = await service.submitRestRecord({
        seafarerRef: assertString(body, "seafarerRef"),
        vesselRef: assertString(body, "vesselRef"),
        recordDate: assertString(body, "recordDate"),
        periods: periodsValue as RestHourPeriod[],
      }, idempotencyKey(request), principal);
      if (result.created) {
        metrics.increment("resthours_records_submitted_total", {});
        for (const flag of result.flags) {
          metrics.increment("resthours_flags_total", { rule: flag.rule });
        }
      }
      return { status: result.created ? 201 : 200, body: result };
    }),
    "GET /v1/rest-hours/records/mine": route(/^\/v1\/rest-hours\/records\/mine$/, [], [ROLE_SEAFARER], { resource: "rest-hours", action: "read-own", classification: "CONFIDENTIAL" }, async (request) => {
      const principal = assertWelfarePrincipal(request);
      const range = {
        ...(request.query["from"] !== undefined ? { from: request.query["from"] } : {}),
        ...(request.query["to"] !== undefined ? { to: request.query["to"] } : {}),
        ...(request.query["vessel_ref"] !== undefined ? { vesselRef: request.query["vessel_ref"] } : {}),
      };
      const result = await service.myRestRecords(principal.subject, range);
      if (result.missingCount !== undefined && result.missingCount > 0) {
        const vesselLabel = request.query["vessel_ref"] === undefined ? "unspecified" : sha256Hex(request.query["vessel_ref"]).slice(0, 12);
        for (let index = 0; index < result.missingCount; index += 1) {
          metrics.increment("resthours_records_missing_total", { vessel: vesselLabel });
        }
      }
      return { status: 200, body: result };
    }),
    "GET /v1/rest-hours/flags": route(/^\/v1\/rest-hours\/flags$/, [], [ROLE_NIMASA_INSPECTOR, ROLE_AUDITOR], { resource: "rest-hours", action: "flags-read", classification: "CONFIDENTIAL" }, async (request) => {
      const vesselRef = request.query["vessel_ref"];
      const flags = await service.listRestFlags(vesselRef === undefined ? {} : { vesselRef });
      return { status: 200, body: { flags } };
    }),
  };
}

function assertWelfarePrincipal(request: RouteRequest): AuthenticatedPrincipal {
  if (request.principal === undefined) throw new ServiceError(401, "authentication is required");
  return request.principal;
}
