import { stripControlCharacters } from '../common/sanitize';
import { summarizeStride } from './strideAnalyzer';
import { STRIDE_CATEGORIES, StrideAnalysis, StrideThreat } from './types';

const RULE = '────────────────────────────';
/** Upper bounds on what is listed individually, to keep the Output Channel readable. */
const MAX_THREATS_LISTED = 60;
const MAX_OBSERVATIONS_SHOWN = 4;
const MAX_NOT_ASSESSED_LISTED = 30;

/** Multi-line report section for the Output Channel (appended after the architecture model report). */
export function formatStrideReport(analysis: StrideAnalysis): string[] {
  const summary = summarizeStride(analysis);
  const lines: string[] = [
    'STRIDE Threat Analysis',
    RULE,
    'Candidate threats for REVIEW. They are not confirmed vulnerabilities, and they are not prioritised or scored.',
    'Each one separates what was observed in the architecture model from what is assumed and what cannot be seen.',
    '',
    `Candidate Threats (${summary.threatCount}):`,
  ];

  if (summary.threatCount === 0) {
    lines.push('  None');
  }
  for (const category of STRIDE_CATEGORIES) {
    const n = summary.byCategory[category];
    if (n) lines.push(`  ${category}: ${n}`);
  }
  if (summary.threatCount > 0) {
    lines.push(
      `  Basis: ${summary.byBasis['observed'] ?? 0} observed condition(s), ${summary.byBasis['assumption-dependent'] ?? 0} assumption-dependent`
    );
  }

  let listed = 0;
  for (const category of STRIDE_CATEGORIES) {
    const inCategory = analysis.threats.filter((t) => t.category === category);
    if (inCategory.length === 0) continue;
    lines.push('', `${category} (${inCategory.length})`);
    for (const threat of inCategory) {
      if (listed >= MAX_THREATS_LISTED) break;
      lines.push(...threatLines(threat));
      listed++;
    }
  }
  if (summary.threatCount > listed) {
    lines.push('', `  … and ${summary.threatCount - listed} more candidate threat(s) not listed.`);
  }

  if (analysis.notAssessed.length > 0) {
    lines.push('', `Not Assessed (${analysis.notAssessed.length}) — required information is missing:`);
    for (const item of analysis.notAssessed.slice(0, MAX_NOT_ASSESSED_LISTED)) {
      lines.push(`  • ${item.ruleId} — ${item.targetName}: ${item.reason}`);
    }
    if (analysis.notAssessed.length > MAX_NOT_ASSESSED_LISTED) {
      lines.push(`  … and ${analysis.notAssessed.length - MAX_NOT_ASSESSED_LISTED} more not listed.`);
    }
  }

  lines.push('', 'Analysis Limitations:', ...analysis.limitations.map((l) => `  • ${l}`));

  if (analysis.warnings.length > 0) {
    lines.push('', 'STRIDE Warnings:', ...analysis.warnings.map((w) => `  • ${w}`));
  }

  lines.push(
    '',
    analysis.threats.length === 0 && analysis.warnings.length > 0
      ? 'STRIDE analysis completed with warnings; no candidate threats were produced.'
      : analysis.warnings.length > 0
        ? 'STRIDE analysis completed with warnings.'
        : 'STRIDE analysis completed successfully.'
  );
  return lines.map(stripControlCharacters); // names come from the scanned project: no forged lines
}

/** Short sentence for the notification toast. */
export function formatStrideSummary(analysis: StrideAnalysis): string {
  const s = summarizeStride(analysis);
  return `STRIDE: ${s.threatCount} candidate ${s.threatCount === 1 ? 'threat' : 'threats'} for review.`;
}

function threatLines(t: StrideThreat): string[] {
  const lines = [`  • ${t.ruleId}  ${t.title}`, `      target: ${t.target.kind} "${t.target.name}"   basis: ${t.basis}   id: ${t.id}`];
  for (const o of t.observations.slice(0, MAX_OBSERVATIONS_SHOWN)) {
    const first = o.evidence[0];
    lines.push(`      observed: ${o.statement}`);
    lines.push(`        evidence: ${first.description} [rule: ${first.rule}]${o.evidence.length > 1 ? ` (+${o.evidence.length - 1} more)` : ''}`);
  }
  if (t.observations.length > MAX_OBSERVATIONS_SHOWN) {
    lines.push(`      observed: … and ${t.observations.length - MAX_OBSERVATIONS_SHOWN} more observation(s).`);
  }
  for (const a of t.assumptions) lines.push(`      assumed: ${a}`);
  for (const l of t.limitations) lines.push(`      limitation: ${l}`);
  return lines;
}
