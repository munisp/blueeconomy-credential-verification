/**
 * Minimal JSON Schema (2020-12 subset) validator used by the schema-drift
 * guard test to prove committed contracts actually accept the documents the
 * code produces. Supports the keyword subset used by this repository's
 * contracts: type, const, enum, required, properties, additionalProperties,
 * items, minItems, uniqueItems, minLength, maxLength, minimum, pattern.
 */

type SchemaNode = Record<string, unknown>;

export function validateAgainstSchema(value: unknown, schema: SchemaNode, path = "$"): string[] {
  const errors: string[] = [];
  const fail = (message: string): void => {
    errors.push(`${path}: ${message}`);
  };

  if (schema["const"] !== undefined && !deepEqual(value, schema["const"])) {
    fail(`must equal ${JSON.stringify(schema["const"])}`);
    return errors;
  }
  if (Array.isArray(schema["enum"]) && !(schema["enum"] as unknown[]).some((entry) => deepEqual(entry, value))) {
    fail(`must be one of ${JSON.stringify(schema["enum"])}`);
    return errors;
  }

  const type = schema["type"];
  if (typeof type === "string" && !matchesType(value, type)) {
    fail(`must be of type ${type}`);
    return errors;
  }

  if (typeof value === "string") {
    if (typeof schema["minLength"] === "number" && value.length < schema["minLength"]) fail(`length must be >= ${schema["minLength"]}`);
    if (typeof schema["maxLength"] === "number" && value.length > schema["maxLength"]) fail(`length must be <= ${schema["maxLength"]}`);
    if (typeof schema["pattern"] === "string" && new RegExp(schema["pattern"]).test(value) === false) {
      fail(`must match pattern ${schema["pattern"]}`);
    }
  }

  if (typeof value === "number") {
    if (schema["type"] === "integer" && !Number.isInteger(value)) fail("must be an integer");
    if (typeof schema["minimum"] === "number" && value < schema["minimum"]) fail(`must be >= ${schema["minimum"]}`);
  }

  if (Array.isArray(value)) {
    if (typeof schema["minItems"] === "number" && value.length < schema["minItems"]) fail(`must contain at least ${schema["minItems"]} items`);
    if (schema["uniqueItems"] === true && new Set(value.map((entry) => JSON.stringify(entry))).size !== value.length) {
      fail("items must be unique");
    }
    const items = schema["items"];
    if (typeof items === "object" && items !== null) {
      value.forEach((entry, index) => {
        errors.push(...validateAgainstSchema(entry, items as SchemaNode, `${path}[${index}]`));
      });
    }
  }

  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    const required = schema["required"];
    if (Array.isArray(required)) {
      for (const field of required as string[]) {
        if (!(field in record)) fail(`missing required property '${field}'`);
      }
    }
    const properties = schema["properties"];
    if (typeof properties === "object" && properties !== null) {
      for (const [field, child] of Object.entries(properties as Record<string, SchemaNode>)) {
        if (field in record) {
          errors.push(...validateAgainstSchema(record[field], child, `${path}.${field}`));
        }
      }
      if (schema["additionalProperties"] === false) {
        for (const field of Object.keys(record)) {
          if (!(field in (properties as Record<string, unknown>))) fail(`additional property '${field}' is not allowed`);
        }
      }
    }
  }
  return errors;
}

function matchesType(value: unknown, type: string): boolean {
  switch (type) {
    case "object": return typeof value === "object" && value !== null && !Array.isArray(value);
    case "array": return Array.isArray(value);
    case "string": return typeof value === "string";
    case "boolean": return typeof value === "boolean";
    case "integer": return typeof value === "number" && Number.isInteger(value);
    case "number": return typeof value === "number";
    case "null": return value === null;
    default: return false;
  }
}

function deepEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}
