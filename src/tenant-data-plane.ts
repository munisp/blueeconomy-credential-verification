export function assertTenantId(value: string): string {
  if (!/^tenant-[A-Za-z0-9._:-]{3,128}$/.test(value)) throw new Error("invalid tenant identifier");
  return value;
}

export function tenantKafkaTopic(tenantId: string, domain: string): string {
  assertTenantId(tenantId);
  if (!/^[a-z][a-z0-9.-]{1,96}$/.test(domain)) throw new Error("invalid Kafka domain");
  return `blueeconomy.${tenantId}.${domain}`;
}

export function tenantObjectPath(tenantId: string, domain: string, objectId: string): string {
  assertTenantId(tenantId);
  if (!/^[a-z][a-z0-9._-]{1,96}$/.test(domain) || !/^[A-Za-z0-9._:-]{1,256}$/.test(objectId)) throw new Error("invalid tenant object path segment");
  return `tenants/${tenantId}/${domain}/${objectId}`;
}

export function assertTenantBoundRecord(claimTenantId: string, recordTenantId: string): void {
  if (assertTenantId(claimTenantId) !== assertTenantId(recordTenantId)) throw new Error("cross-tenant record access denied");
}
