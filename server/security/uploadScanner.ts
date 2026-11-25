import type { DocumentClassification } from '../pdp/policyEngine.ts';

export interface DlpFindingCount {
  pattern: string;
  count: number;
}

export interface UploadInspectionResult {
  signatureValid: boolean;
  activeContentBlocked: boolean;
  activeContentTokens: string[];
  dlpStatus: 'CLEAN' | 'SENSITIVE_MARKERS_DETECTED';
  matchedPatterns: string[];
  patternCounts: Record<string, number>;
  dlpFindings: DlpFindingCount[];
  suggestedClassification: DocumentClassification;
  approvalRequired: boolean;
  externalAiClassifier: 'OFF_PROPOSED';
  dlpWarning: string | null;
}

const DISALLOWED_PDF_TOKENS: Array<{ label: string; pattern: RegExp }> = [
  { label: '/JavaScript', pattern: /\/JavaScript\b/i },
  { label: '/JS', pattern: /\/JS\b/ },
  { label: '/Launch', pattern: /\/Launch\b/i },
  { label: '/EmbeddedFile', pattern: /\/EmbeddedFile\b/i },
];

const DLP_PATTERN_RULES: Array<{
  code: string;
  severity: 'INTERNAL' | 'CONFIDENTIAL';
  pattern: RegExp;
}> = [
  {
    code: 'STUDENT_ID',
    severity: 'INTERNAL',
    pattern: /\b(?:STU|REG|ROLL|CS|EC|ME|CE)[-\s]?\d{4,8}\b|\b20\d{2}[A-Z]{2,4}\d{3,5}\b/g,
  },
  {
    code: 'EMAIL',
    severity: 'INTERNAL',
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    code: 'PHONE_NUMBER',
    severity: 'INTERNAL',
    pattern: /\b(?:\+?\d{1,3}[\s.-])?(?:\(?\d{3}\)?[\s.-])\d{3}[\s.-]\d{4}\b/g,
  },
  {
    code: 'CONFIDENTIAL_KEYWORD',
    severity: 'CONFIDENTIAL',
    pattern: /\b(?:CONFIDENTIAL|TOP SECRET|RESTRICTED|EXAMINATION PAPER|ANSWER KEY|QUESTION PAPER|GRADE SHEET|TRANSCRIPT)\b/gi,
  },
  {
    code: 'PRIVATE_KEY',
    severity: 'CONFIDENTIAL',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  },
  {
    code: 'GOV_ID_FORMAT',
    severity: 'CONFIDENTIAL',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
];

const CLASSIFICATION_RANK: Record<DocumentClassification, number> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
};

/**
 * Deterministic server-side local DLP & rule-based classifier.
 * Zero external AI calls are made; external AI classification remains OFF (Proposed).
 * Never logs or returns raw matched PII strings—only pattern names and counts.
 */
export function inspectUploadedPdf(
  buffer: Buffer,
  requestedClassification: DocumentClassification
): UploadInspectionResult {
  const signatureValid = buffer.byteLength >= 5 && buffer.subarray(0, 5).toString('ascii') === '%PDF-';
  const asciiSample = buffer.toString('latin1');

  const activeContentTokens: string[] = [];
  for (const rule of DISALLOWED_PDF_TOKENS) {
    if (rule.pattern.test(asciiSample)) {
      activeContentTokens.push(rule.label);
    }
  }

  const matchedPatterns: string[] = [];
  const patternCounts: Record<string, number> = {};
  const dlpFindings: DlpFindingCount[] = [];
  let hasConfidentialRule = false;
  let internalCategoryCount = 0;

  for (const rule of DLP_PATTERN_RULES) {
    const matches = asciiSample.match(rule.pattern);
    if (matches && matches.length > 0) {
      matchedPatterns.push(rule.code);
      patternCounts[rule.code] = matches.length;
      dlpFindings.push({ pattern: rule.code, count: matches.length });
      if (rule.severity === 'CONFIDENTIAL') {
        hasConfidentialRule = true;
      } else {
        internalCategoryCount += 1;
      }
    }
  }

  let suggestedClassification: DocumentClassification = 'PUBLIC';
  if (hasConfidentialRule || internalCategoryCount >= 2) {
    suggestedClassification = 'CONFIDENTIAL';
  } else if (internalCategoryCount === 1) {
    suggestedClassification = 'INTERNAL';
  }

  const dlpStatus: UploadInspectionResult['dlpStatus'] =
    matchedPatterns.length > 0 ? 'SENSITIVE_MARKERS_DETECTED' : 'CLEAN';

  const suggestedHigherThanRequested =
    CLASSIFICATION_RANK[suggestedClassification] > CLASSIFICATION_RANK[requestedClassification];

  const approvalRequired =
    dlpStatus === 'SENSITIVE_MARKERS_DETECTED' || suggestedHigherThanRequested;

  const dlpWarning = suggestedHigherThanRequested
    ? `Local DLP detected [${matchedPatterns.join(', ')}] and recommends ${suggestedClassification} (requested ${requestedClassification}). Human HOD/Admin approval is required before sharing.`
    : dlpStatus === 'SENSITIVE_MARKERS_DETECTED'
      ? `Local DLP detected [${matchedPatterns.join(', ')}]. Human HOD/Admin confirmation is required before activating document sharing.`
      : null;

  return {
    signatureValid,
    activeContentBlocked: activeContentTokens.length > 0,
    activeContentTokens,
    dlpStatus,
    matchedPatterns,
    patternCounts,
    dlpFindings,
    suggestedClassification,
    approvalRequired,
    externalAiClassifier: 'OFF_PROPOSED',
    dlpWarning,
  };
}
