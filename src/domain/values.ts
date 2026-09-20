/**
 * Typed HTTP value model — no `any` / `unknown`.
 * Covers common query / JSON / multipart scalar shapes.
 */

import { Buffer } from 'node:buffer';

export type JsonPrimitive = string | number | boolean | null;

export type JsonArray = readonly JsonValue[];

export interface JsonObject {
  readonly [key: string]: JsonValue | undefined;
}

export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

export type HeaderValue = string | string[] | undefined;

export type HeaderMap = Readonly<Record<string, HeaderValue>>;

/**
 * Query values are not always scalars: Express' default `extended` parser (and
 * Fastify with `querystringParser`) turns `?filter[status]=open` into a nested
 * object, and `?a[]=1&a[]=2` into an array of them.
 */
export type QueryValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | readonly QueryValue[]
  | QueryObject;

export interface QueryObject {
  readonly [key: string]: QueryValue;
}

export type QueryMap = Readonly<Record<string, QueryValue>>;

/** Depth cap so a hostile deeply-nested query cannot drive recursion cost. */
const MAX_QUERY_DEPTH = 6;

export type CookieMap = Readonly<Record<string, string>>;

export interface UploadedFile {
  readonly fieldname?: string;
  readonly name?: string;
  readonly filename?: string;
  readonly originalname?: string;
}

export type FilesBag =
  | readonly UploadedFile[]
  | Readonly<Record<string, UploadedFile | readonly UploadedFile[]>>;

function isQueryArray(value: QueryValue): value is readonly QueryValue[] {
  return Array.isArray(value);
}

function flattenQuery(value: QueryValue, depth: number): string {
  if (value === undefined || value === null) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (depth >= MAX_QUERY_DEPTH) {
    return '';
  }
  if (isQueryArray(value)) {
    return value.map((item) => flattenQuery(item, depth + 1)).join(',');
  }
  return Object.keys(value)
    .map((key) => `${key}=${flattenQuery(value[key], depth + 1)}`)
    .join('&');
}

/**
 * Flatten a header / query value into a single string for matching.
 *
 * Nested objects are rendered back as `key=value&key=value`, which keeps
 * bracketed parameter **names** visible to rules — that is how
 * `?user[$ne]=null` reaches the NoSQL operator rule.
 */
export function scalarToString(value: HeaderValue | QueryValue): string {
  return flattenQuery(value, 0);
}

/** Serialize a JSON-compatible body for payload inspection. */
export function jsonToString(value: JsonValue | undefined): string {
  if (value === undefined || value === null) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}

/** Convert Buffer | string | JsonValue into a raw body string. */
export function bodyToString(
  value: string | Buffer | JsonValue | undefined,
): string {
  if (value === undefined || value === null) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (Buffer.isBuffer(value)) {
    return value.toString('utf8');
  }
  return jsonToString(value);
}

/**
 * Defer `bodyToString` (which can `JSON.stringify` a large parsed body) until
 * the WAF actually reads the body — i.e. only when some active rule's field
 * resolution needs it. Adapters call `getRaw()` synchronously (already
 * parsed by the framework), so laziness is safe and result is cached after
 * the first call: {@link WafHttpContext.getRawBody} is memoized per request
 * upstream (field-resolver memo) but adapters are also used directly, so
 * this keeps the guarantee "computed at most once" self-contained here too.
 */
export function lazyBodyToString(
  getRaw: () => string | Buffer | JsonValue | undefined,
): () => string {
  let cached: string | undefined;
  return () => {
    if (cached === undefined) {
      cached = bodyToString(getRaw());
    }
    return cached;
  };
}

function isFileList(
  files: FilesBag,
): files is readonly UploadedFile[] {
  return Array.isArray(files);
}

function isUploadedFileList(
  entry: UploadedFile | readonly UploadedFile[],
): entry is readonly UploadedFile[] {
  return Array.isArray(entry);
}

/** Normalize multipart / express file bags into a flat immutable list. */
export function normalizeFiles(
  files: FilesBag | undefined,
): readonly UploadedFile[] {
  if (!files) {
    return [];
  }
  if (isFileList(files)) {
    return [...files];
  }
  const bag: Readonly<Record<string, UploadedFile | readonly UploadedFile[]>> =
    files;
  return Object.keys(bag).flatMap((fieldname) => {
    const entry = bag[fieldname];
    if (entry === undefined) {
      return [];
    }
    if (isUploadedFileList(entry)) {
      return entry.map((file) => ({
        ...file,
        fieldname: file.fieldname ?? fieldname,
      }));
    }
    return [{ ...entry, fieldname: entry.fieldname ?? fieldname }];
  });
}

export function fileDisplayName(file: UploadedFile): string {
  return file.name ?? file.filename ?? file.originalname ?? '';
}
