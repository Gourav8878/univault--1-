import crypto from 'node:crypto';
import { env } from '../config/env.ts';

export interface ClassificationHashInput {
  documentId: string;
  departmentId: string;
  classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL';
  version: number;
}

export function getClassificationHashMode(): 'hmac-sha256' | 'canonical-sha256' {
  return env.classificationHmacKey ? 'hmac-sha256' : 'canonical-sha256';
}

export function computeClassificationHash(input: ClassificationHashInput): string {
  const canonicalPayload = JSON.stringify({
    documentId: input.documentId,
    departmentId: input.departmentId,
    classification: input.classification,
    version: input.version,
  });

  if (env.classificationHmacKey) {
    return crypto
      .createHmac('sha256', env.classificationHmacKey)
      .update(canonicalPayload)
      .digest('hex');
  }

  return crypto
    .createHash('sha256')
    .update(`univault-classification-v1:${canonicalPayload}`)
    .digest('hex');
}

export function verifyClassificationHash(
  input: ClassificationHashInput,
  storedHash: string | null | undefined
): boolean {
  if (!storedHash || storedHash.trim().length !== 64) {
    return false;
  }

  const expected = computeClassificationHash(input);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(storedHash.trim(), 'hex')
    );
  } catch {
    return false;
  }
}
