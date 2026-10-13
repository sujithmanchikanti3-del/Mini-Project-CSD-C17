import {
  ArchitectureComponent,
  ArchitectureEvidence,
  ArchitectureModel,
  ArchitectureRelationship,
  RelationshipType,
} from '../architecture/types';

/**
 * V0.5 — Deterministic STRIDE threat analysis.
 *
 * Everything produced here is a CANDIDATE threat for human review. It is derived only from the
 * V0.4 architecture model (what the scanned files declare). It is never a confirmed finding:
 * the model contains no data flows, trust boundaries, authentication/TLS configuration, or
 * source-code behaviour, so each threat separates
 *   - observations : facts taken from the model, each with its evidence,
 *   - assumptions  : what would have to be true for the threat to apply (NOT established by the model),
 *   - limitations  : what this analysis cannot see.
 * There is deliberately no severity, likelihood, score, CVE, or mitigation here (later milestones).
 */

export const STRIDE_CATEGORIES = [
  'Spoofing',
  'Tampering',
  'Repudiation',
  'Information Disclosure',
  'Denial of Service',
  'Elevation of Privilege',
] as const;
export type StrideCategory = (typeof STRIDE_CATEGORIES)[number];

/**
 * observed              the triggering condition is itself a declared fact (e.g. image tag "latest").
 * assumption-dependent  applicability rests on one or more explicit assumptions the model does not establish.
 */
export type ThreatBasis = 'observed' | 'assumption-dependent';

export interface ThreatObservation {
  /** A statement of fact about the model, or about the absence of something in the inspected declarations. */
  statement: string;
  /** Evidence copied from the architecture model element(s) the statement is based on. Never empty. */
  evidence: ArchitectureEvidence[];
}

export interface ThreatTarget {
  kind: 'component' | 'relationship';
  /** Identifier of an element of the V0.4 architecture model. */
  id: string;
  /** Display name (component name, or "source → target" for a relationship). */
  name: string;
}

export interface StrideThreat {
  /** Deterministic: `threat:<ruleId>|<targetId>` plus an optional `|<qualifier>`. */
  id: string;
  ruleId: string;
  category: StrideCategory;
  title: string;
  description: string;
  basis: ThreatBasis;
  target: ThreatTarget;
  /** Further model elements the threat refers to (all ids exist in the model). */
  relatedComponentIds: string[];
  relatedRelationshipIds: string[];
  /** Never empty. */
  observations: ThreatObservation[];
  /** Never empty when basis is 'assumption-dependent'. */
  assumptions: string[];
  /** Never empty. */
  limitations: string[];
}

/** A rule that could not be assessed for an element because required information is missing. */
export interface NotAssessedItem {
  ruleId: string;
  category: StrideCategory;
  targetId: string;
  targetName: string;
  reason: string;
}

export interface StrideAnalysis {
  /** Sorted: STRIDE category order, then rule id, then threat id. */
  threats: StrideThreat[];
  notAssessed: NotAssessedItem[];
  /** What this analysis can never see, regardless of the project. */
  limitations: string[];
  /** Problems affecting completeness (incomplete model, a rule that failed, ...). */
  warnings: string[];
}

export interface StrideSummary {
  threatCount: number;
  byCategory: Partial<Record<StrideCategory, number>>;
  byBasis: Partial<Record<ThreatBasis, number>>;
  notAssessedCount: number;
}

/* ------------------------------ rule engine internals ------------------------------ */

/** What a rule reports for one model element. */
export type RuleFinding =
  | {
      kind: 'threat';
      target: ThreatTarget;
      /** Added to the id when one target can carry several threats from the same rule (e.g. per manifest). */
      qualifier?: string;
      title: string;
      description: string;
      relatedComponentIds?: string[];
      relatedRelationshipIds?: string[];
      observations: ThreatObservation[];
      assumptions: string[];
      limitations: string[];
    }
  | { kind: 'not-assessed'; targetId: string; targetName: string; reason: string };

export interface StrideRule {
  id: string;
  category: StrideCategory;
  basis: ThreatBasis;
  /** One-line description of when the rule fires (also used by the documentation test). */
  summary: string;
  evaluate(ctx: RuleContext): RuleFinding[];
}

/** Read-only, index-based view of the architecture model handed to every rule. */
export interface RuleContext {
  readonly model: ArchitectureModel;
  component(id: string): ArchitectureComponent | undefined;
  componentsOfType(type: ArchitectureComponent['type']): ArchitectureComponent[];
  /** The project module (Application or Unknown) that `contains` the component, if the model establishes one. */
  moduleOf(componentId: string): ArchitectureComponent | undefined;
  /** Library components the module declares via `declares-dependency`. */
  declaredLibraries(moduleId: string): ArchitectureComponent[];
  relationshipsOfType(type: RelationshipType): ArchitectureRelationship[];
  /** Relationships whose target is the component, optionally restricted to one type. */
  incoming(componentId: string, type?: RelationshipType): ArchitectureRelationship[];
}
