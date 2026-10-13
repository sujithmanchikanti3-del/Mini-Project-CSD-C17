import { ArchitectureComponent, ArchitectureModel, ArchitectureRelationship, RelationshipType } from '../architecture/types';
import { sanitizeErrorMessage } from '../common/sanitize';
import { GLOBAL_LIMITATIONS, STRIDE_RULES } from './strideRules';
import {
  NotAssessedItem,
  RuleContext,
  RuleFinding,
  STRIDE_CATEGORIES,
  StrideAnalysis,
  StrideRule,
  StrideSummary,
  StrideThreat,
} from './types';

/**
 * V0.5 STRIDE analyzer.
 *
 * Pure and deterministic: the V0.4 architecture model in, candidate threats out. No filesystem,
 * no network, no `vscode`, no randomness, no timestamps. The same model always yields the same
 * threats with the same identifiers in the same order, regardless of the order of the arrays in
 * the model. A failing rule never discards the output of the others.
 */

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const byId = <T extends { id: string }>(a: T, b: T): number => compare(a.id, b.id);

class ModelContext implements RuleContext {
  private readonly components = new Map<string, ArchitectureComponent>();

  constructor(readonly model: ArchitectureModel) {
    for (const c of model.components) {
      this.components.set(c.id, c);
    }
  }

  component(id: string): ArchitectureComponent | undefined {
    return this.components.get(id);
  }

  componentsOfType(type: ArchitectureComponent['type']): ArchitectureComponent[] {
    return this.model.components.filter((c) => c.type === type).sort(byId);
  }

  moduleOf(componentId: string): ArchitectureComponent | undefined {
    const sources = this.model.relationships
      .filter((r) => r.type === 'contains' && r.targetId === componentId)
      .map((r) => this.components.get(r.sourceId))
      .filter((c): c is ArchitectureComponent => c !== undefined && (c.type === 'Application' || c.type === 'Unknown'))
      .sort(byId);
    return sources[0];
  }

  declaredLibraries(moduleId: string): ArchitectureComponent[] {
    const libs = new Map<string, ArchitectureComponent>();
    for (const r of this.model.relationships) {
      if (r.type === 'declares-dependency' && r.sourceId === moduleId) {
        const lib = this.components.get(r.targetId);
        if (lib && lib.type === 'Library/Dependency') libs.set(lib.id, lib);
      }
    }
    return [...libs.values()].sort(byId);
  }

  relationshipsOfType(type: RelationshipType): ArchitectureRelationship[] {
    return this.model.relationships.filter((r) => r.type === type).sort(byId);
  }

  incoming(componentId: string, type?: RelationshipType): ArchitectureRelationship[] {
    return this.model.relationships.filter((r) => r.targetId === componentId && (type === undefined || r.type === type)).sort(byId);
  }
}

/** Analyze a model. `rules` is injectable so tests can exercise failure isolation and invariant checks. */
export function analyzeStride(model: ArchitectureModel, rules: readonly StrideRule[] = STRIDE_RULES): StrideAnalysis {
  const warnings: string[] = [];
  const result: StrideAnalysis = { threats: [], notAssessed: [], limitations: [...GLOBAL_LIMITATIONS], warnings };

  if (model.components.length === 0) {
    warnings.push('The architecture model is empty, so no rules were evaluated.');
    return result;
  }
  if (model.warnings.length > 0) {
    warnings.push(
      `The architecture model reports ${model.warnings.length} warning(s) and may be incomplete; this analysis covers only what the model contains.`
    );
  }

  const ctx = new ModelContext(model);
  const threats = new Map<string, StrideThreat>();
  const notAssessed = new Map<string, NotAssessedItem>();
  const exists = (id: string): boolean => ctx.component(id) !== undefined || model.relationships.some((r) => r.id === id);

  for (const rule of rules) {
    let findings: RuleFinding[];
    try {
      findings = rule.evaluate(ctx);
    } catch (error) {
      warnings.push(`Rule ${rule.id} could not be evaluated: ${sanitizeErrorMessage(error)}`);
      continue;
    }

    for (const finding of findings) {
      if (finding.kind === 'not-assessed') {
        const key = `${rule.id}|${finding.targetId}|${finding.reason}`;
        if (!notAssessed.has(key)) {
          notAssessed.set(key, {
            ruleId: rule.id,
            category: rule.category,
            targetId: finding.targetId,
            targetName: finding.targetName,
            reason: finding.reason,
          });
        }
        continue;
      }

      const id = `threat:${rule.id}|${finding.target.id}${finding.qualifier !== undefined ? `|${finding.qualifier}` : ''}`;
      const related = [...(finding.relatedComponentIds ?? []), ...(finding.relatedRelationshipIds ?? [])];
      const problem =
        finding.observations.length === 0 || finding.observations.some((o) => o.evidence.length === 0)
          ? 'it has no evidenced observation'
          : finding.limitations.length === 0
            ? 'it states no limitation'
            : rule.basis === 'assumption-dependent' && finding.assumptions.length === 0
              ? 'it is assumption-dependent but states no assumption'
              : ![finding.target.id, ...related].every(exists)
                ? 'it refers to an element that is not in the model'
                : threats.has(id)
                  ? 'its identifier is not unique'
                  : undefined;
      if (problem) {
        warnings.push(`Rule ${rule.id} produced a threat for "${finding.target.name}" that was dropped: ${problem}.`);
        continue;
      }

      threats.set(id, {
        id,
        ruleId: rule.id,
        category: rule.category,
        title: finding.title,
        description: finding.description,
        basis: rule.basis,
        target: finding.target,
        relatedComponentIds: [...(finding.relatedComponentIds ?? [])],
        relatedRelationshipIds: [...(finding.relatedRelationshipIds ?? [])],
        observations: finding.observations,
        assumptions: finding.assumptions,
        limitations: finding.limitations,
      });
    }
  }

  const order = (category: string): number => STRIDE_CATEGORIES.indexOf(category as (typeof STRIDE_CATEGORIES)[number]);
  result.threats = [...threats.values()].sort((a, b) => order(a.category) - order(b.category) || compare(a.ruleId, b.ruleId) || compare(a.id, b.id));
  result.notAssessed = [...notAssessed.values()].sort(
    (a, b) => order(a.category) - order(b.category) || compare(a.ruleId, b.ruleId) || compare(a.targetId, b.targetId) || compare(a.reason, b.reason)
  );
  return result;
}

/** Analysis for the case where the analyzer itself failed; keeps the pipeline alive. */
export function emptyStrideAnalysis(warning: string): StrideAnalysis {
  return { threats: [], notAssessed: [], limitations: [...GLOBAL_LIMITATIONS], warnings: [warning] };
}

export function summarizeStride(analysis: StrideAnalysis): StrideSummary {
  const byCategory: StrideSummary['byCategory'] = {};
  const byBasis: StrideSummary['byBasis'] = {};
  for (const t of analysis.threats) {
    byCategory[t.category] = (byCategory[t.category] ?? 0) + 1;
    byBasis[t.basis] = (byBasis[t.basis] ?? 0) + 1;
  }
  return { threatCount: analysis.threats.length, byCategory, byBasis, notAssessedCount: analysis.notAssessed.length };
}
