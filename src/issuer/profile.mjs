import { didWebFromBase } from './did-web.mjs';

/** Base URL of the static site that serves the issuer's DID document and status list. */
export const SITE_BASE = process.env.MOHAR_SITE_BASE ?? 'https://doryoysterpie.github.io/mohar-ethmumbai-26';

export const ISSUER_DID = didWebFromBase(SITE_BASE);

/** Credential type of the eligibility credential. */
export const VCT = `${SITE_BASE}/vct/tet-eligibility/v1`;

/** Published path of the status list, relative to SITE_BASE. */
export const STATUS_LIST_PATH = 'status/tet-eligibility.jwt';
export const STATUS_LIST_URI = `${SITE_BASE}/${STATUS_LIST_PATH}`;

export const ISSUING_BODY = 'CBSE (simulated)';

/** Claims that are selectively disclosable, in credential order. */
export const DISCLOSABLE = [
  'qualified', 'paper', 'stage', 'exam_session', 'issuing_body', 'certificate_commitment', 'name',
  'roll_no', 'dob', 'category', 'mother_name', 'father_or_husband_name', 'marks',
];

/** Claims carried so the credential mirrors the certificate, never disclosed in an eligibility presentation. */
export const NEVER_PRESENTED = ['roll_no', 'dob', 'category', 'mother_name', 'father_or_husband_name', 'marks'];

/** Fields every certificate must carry before a credential is issued for it. */
export const CERTIFICATE_FIELDS = [
  'notice', 'name', 'roll_no', 'dob', 'category', 'mother_name', 'father_or_husband_name',
  'paper', 'stage', 'exam_session', 'qualified', 'marks',
];
