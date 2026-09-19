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

export type QueryValue = string | string[] | undefined;

export type QueryMap = Readonly<Record<string, QueryValue>>;

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

/** Flatten a header / query value into a single string for matching. */
export function scalarToString(value: HeaderValue | QueryValue): string {
  if (value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  return value.join(',');
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
