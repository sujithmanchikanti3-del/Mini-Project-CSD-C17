import { redactCredentials } from '../common/sanitize';
import { WorkspaceScanResult } from '../scanner/types';
import {
  DetectedDependency,
  DetectedTechnology,
  Ecosystem,
  TechnologyInventory,
  TechnologyScope,
} from '../scanner/technology/types';
import {
  RULE_IDS,
  DependencyRole,
  DependencyRule,
  databaseLabelForImage,
  matchDependencyRule,
} from './architectureRules';
import {
  ArchitectureComponent,
  ArchitectureEvidence,
  ArchitectureModel,
  ArchitectureRelationship,
  ArchitectureSummary,
  Certainty,
  ComponentTechnology,
  ComponentType,
  ContainerRole,
  RelationshipType,
} from './types';

/**
 * V0.4 architecture model construction.
 *
 * Pure and deterministic: (V0.2 scan, V0.3 inventory) in, model out. No filesystem, no network,
 * no `vscode`, no execution of anything. The same inputs always yield identical ids and ordering.
 * Only DECLARATIONS found in scanned files become relationships; no runtime behaviour is inferred.
 */

const ROLE_NOTE_ROOT =
  'Whether this project is an application, library or tool is not determined from the scanned files.';
const ROLE_NOTE_MODULE =
  'Role of this module (service, library, tool, ...) is not determined from its manifest.';
const NO_ROOT_MANIFEST_NOTE =
  'No project manifest was found at the workspace root, so the project type and its dependencies are not determined from it.';

export function buildArchitectureModel(scan: WorkspaceScanResult, inventory: TechnologyInventory): ArchitectureModel {
  const b = new ModelBuilder();
  const warnings: string[] = [];

  /* ---------- Phase 0: project units (directories that hold a project manifest) ---------- */
  const manifestsByUnit = new Map<string, string[]>();
  for (const file of scan.configurationFiles) {
    if (!isDockerFile(baseName(file))) {
      const dir = dirName(file);
      manifestsByUnit.set(dir, [...(manifestsByUnit.get(dir) ?? []), file]);
    }
  }
  const unitDirs = new Set<string>(['', ...manifestsByUnit.keys()]);
  const units = [...unitDirs].sort(compareUnits);
  const unitFor = (filePath: string): string => nearestUnit(unitDirs, dirName(filePath));
  const sourceInfo = new Map(inventory.sources.map((s) => [s.path, s]));

  /* ---------- Phase 1: Application (root) and module components ---------- */
  for (const unit of units) {
    const manifests = manifestsByUnit.get(unit) ?? [];
    const isRoot = unit === '';
    const evidence: ArchitectureEvidence[] = isRoot
      ? [
          {
            kind: 'workspace-scan',
            source: '.',
            rule: RULE_IDS.workspaceRoot,
            description: `The scanned workspace "${scan.workspaceName}" is modelled as the Application component.`,
            detail: { name: scan.workspaceName },
          },
        ]
      : [];
    for (const manifest of manifests) {
      evidence.push({
        kind: 'manifest-file',
        source: manifest,
        rule: isRoot ? RULE_IDS.projectManifest : RULE_IDS.manifestInSubdirectory,
        description: isRoot
          ? `Project manifest ${manifest} is present.`
          : `Directory "${unit}" contains project manifest ${manifest}.`,
      });
    }

    const uncertainty = [isRoot ? ROLE_NOTE_ROOT : ROLE_NOTE_MODULE];
    if (isRoot && manifests.length === 0) {
      uncertainty.push(NO_ROOT_MANIFEST_NOTE);
    }
    const ecosystems = unique(
      manifests.map((m) => sourceInfo.get(m)?.ecosystem).filter((e): e is Ecosystem => e !== undefined)
    );

    b.upsertComponent({
      id: appId(unit),
      type: isRoot ? 'Application' : 'Unknown',
      name: isRoot ? scan.workspaceName : unit,
      certainty: isRoot ? 'inferred' : 'unknown',
      evidence,
      uncertainty,
      ...(ecosystems.length > 0 ? { ecosystems } : {}),
    });

    if (!isRoot) {
      const parent = nearestUnit(unitDirs, dirName(unit));
      b.relate('contains', appId(parent), appId(unit), evidence, `${b.nameOf(appId(parent))} contains module "${unit}".`);
    }
  }

  /* ---------- Phase 1b: manifests that failed or were only partly read ---------- */
  for (const source of inventory.sources) {
    if (source.status === 'parsed') {
      continue;
    }
    const unitId = appId(unitFor(source.path));
    if (source.status === 'error') {
      const text = `Manifest ${source.path} could not be read (${source.message ?? 'unknown error'}); it contributes nothing to the model.`;
      b.addUncertainty(unitId, text);
      warnings.push(text);
    } else {
      b.addUncertainty(unitId, `Manifest ${source.path} was only partially read (${source.message ?? 'warnings'}).`);
    }
  }
  if (scan.truncated) {
    warnings.push('The workspace scan was truncated; the model may be incomplete.');
  }

  /* ---------- Phase 1c: runtime technologies declared in manifests ---------- */
  for (const tech of inventory.technologies) {
    if (tech.ecosystem === 'Docker') {
      continue;
    }
    b.enrich(appId(unitFor(tech.source)), {
      evidence: [
        {
          kind: 'technology-declaration',
          source: tech.source,
          rule: RULE_IDS.runtimeTechnologyDeclaration,
          description: `${tech.name} ${display(tech.version)} declared in ${tech.source}${tech.reference ? ` (${tech.reference})` : ''}.`,
          detail: { name: tech.name, version: tech.version, ...(tech.reference ? { reference: tech.reference } : {}) },
        },
      ],
      technologies: [
        {
          name: tech.name,
          version: tech.version,
          ecosystem: tech.ecosystem,
          kind: 'runtime',
          source: tech.source,
          ...(tech.notes ? { notes: tech.notes } : {}),
        },
      ],
    });
  }

  /* ---------- Phase 2: dependencies -> Library/Dependency components ---------- */
  const promotions = new Map<string, Array<{ dep: DetectedDependency; rule: DependencyRule; libId: string }>>();
  for (const dep of inventory.dependencies) {
    const unit = unitFor(dep.source);
    const libId = `lib:${dep.ecosystem}|${dep.source}|${dep.category}|${dep.name}`;
    const evidence = dependencyEvidence(dep, RULE_IDS.manifestDeclaresDependency, 'dependency-declaration',
      `${dep.name} ${display(dep.version)} declared in ${dep.source} (${dep.category}).`);

    b.upsertComponent({
      id: libId,
      type: 'Library/Dependency',
      name: dep.name,
      certainty: 'declared',
      evidence: [evidence],
      technologies: [dependencyTechnology(dep)],
    });
    b.relate('declares-dependency', appId(unit), libId, [evidence],
      `${b.nameOf(appId(unit))} declares dependency ${dep.name}.`);

    const rule = matchDependencyRule(dep);
    if (rule) {
      const list = promotions.get(unit) ?? [];
      list.push({ dep, rule, libId });
      promotions.set(unit, list);
    }
  }

  /* ---------- Phase 3: roles inferred from well-known dependencies ---------- */
  for (const unit of units) {
    const found = promotions.get(unit);
    if (!found) {
      continue;
    }
    for (const role of ['frontend', 'backend'] as const) {
      const items = found.filter((f) => f.rule.role === role);
      if (items.length === 0) continue;
      const labels = unique(items.map((i) => i.rule.label));
      const id = `${role}:${unit || '.'}`;
      const type: ComponentType = role === 'frontend' ? 'Frontend' : 'Backend';
      const ruleId = role === 'frontend' ? RULE_IDS.frontendFrameworkDependency : RULE_IDS.backendFrameworkDependency;
      b.upsertComponent({
        id,
        type,
        name: `${type} (${labels.join(', ')})`,
        certainty: 'inferred',
        evidence: [],
        uncertainty: [
          `${type} role is inferred from declared framework dependencies only; where the ${type.toLowerCase()} code lives and how it is run or exposed are not determined.`,
        ],
      });
      for (const { dep, rule, libId } of items) {
        const evidence = dependencyEvidence(dep, ruleId, 'classification-rule',
          `Dependency ${dep.name} ${display(dep.version)} in ${dep.source} is a known ${rule.label} ${role === 'frontend' ? 'frontend framework' : 'server framework'}.`);
        b.enrich(id, { evidence: [evidence], technologies: [dependencyTechnology(dep)] });
        b.relate('contains', appId(unit), id, [evidence], `${b.nameOf(appId(unit))} contains ${b.nameOf(id)}.`);
        b.relate('built-with', id, libId, [evidence], `${b.nameOf(id)} is identified by library ${dep.name}.`);
      }
    }

    // Databases / external services: one component per technology per module; linked from the client library only.
    for (const role of ['database-client', 'external-service-sdk'] as const) {
      const items = found.filter((f) => f.rule.role === role);
      for (const label of unique(items.map((i) => i.rule.label))) {
        const isDb = role === 'database-client';
        const id = `${isDb ? 'db' : 'ext'}:${unit || '.'}|${label}`;
        const type: ComponentType = isDb ? 'Database' : 'External Service';
        b.upsertComponent({
          id,
          type,
          name: label,
          certainty: 'inferred',
          evidence: [],
          uncertainty: [
            isDb
              ? 'Database instance, hosting and connection details are not determined from the scanned files; only a client library for this database is declared.'
              : 'Whether, where and how this service is called at runtime is not determined; only an SDK/client library for it is declared.',
          ],
        });
        for (const { dep, libId } of items.filter((i) => i.rule.label === label)) {
          const evidence = dependencyEvidence(dep, isDb ? RULE_IDS.databaseClientLibrary : RULE_IDS.externalServiceSdk, 'classification-rule',
            `Dependency ${dep.name} ${display(dep.version)} in ${dep.source} is a known ${isDb ? `${label} database client library` : `${label} SDK`}.`);
          b.enrich(id, { evidence: [evidence], technologies: [dependencyTechnology(dep)] });
          b.relate('client-library-for', libId, id, [evidence], `Library ${dep.name} is a client for ${label}.`);
        }
      }
    }
  }

  /* ---------- Phase 4: container images (Dockerfile bases, compose services) ---------- */
  for (const tech of inventory.technologies) {
    if (tech.ecosystem !== 'Docker') {
      continue;
    }
    const unit = unitFor(tech.source);
    addImage(b, tech, appId(unit), dirName(tech.source) !== unit);
  }

  return {
    workspaceName: scan.workspaceName,
    components: b.components(),
    relationships: b.relationships(),
    warnings,
  };
}

/** Model for the case where construction itself failed; keeps the pipeline alive. */
export function emptyArchitectureModel(workspaceName: string, warning: string): ArchitectureModel {
  return { workspaceName, components: [], relationships: [], warnings: [warning] };
}

export function summarizeArchitecture(model: ArchitectureModel): ArchitectureSummary {
  const componentsByType: ArchitectureSummary['componentsByType'] = {};
  for (const c of model.components) {
    componentsByType[c.type] = (componentsByType[c.type] ?? 0) + 1;
  }
  const relationshipsByType: ArchitectureSummary['relationshipsByType'] = {};
  for (const r of model.relationships) {
    relationshipsByType[r.type] = (relationshipsByType[r.type] ?? 0) + 1;
  }
  return {
    componentCount: model.components.length,
    relationshipCount: model.relationships.length,
    componentsByType,
    relationshipsByType,
  };
}

/* ================================ images ================================ */

function addImage(b: ModelBuilder, tech: DetectedTechnology, unitId: string, outsideUnitDirectory: boolean): void {
  const scope: TechnologyScope =
    tech.scope ??
    (baseName(tech.source) === 'Dockerfile'
      ? { kind: 'build-stage', index: 0 }
      : { kind: 'service', name: '(unnamed)' });

  const rawReference = tech.reference ?? tech.name;
  const reference = redactCredentials(rawReference);
  const redacted = reference !== rawReference;
  const notes = [tech.notes, redacted ? 'credentials in the image reference were redacted' : undefined]
    .filter(Boolean)
    .join('; ');
  const imageTech: ComponentTechnology = {
    name: redacted ? reference : tech.name,
    version: redacted ? null : tech.version,
    ecosystem: 'Docker',
    kind: 'image',
    source: tech.source,
    ...(notes ? { notes } : {}),
  };
  const usesVariable = /\$\{?\w/.test(reference);
  const variableNote = usesVariable ? ['Image reference uses a variable; its value is not resolved.'] : [];
  const placementNote = outsideUnitDirectory
    ? [`${tech.source} is located outside the directory of the module it is attributed to; which module it builds or deploys is not determined.`]
    : [];
  const detail = { name: imageTech.name, version: imageTech.version, reference };

  if (scope.kind === 'service') {
    const dbLabel = databaseLabelForImage(imageTech.name);
    const id = `service:${tech.source}|${scope.name}`;
    const evidence: ArchitectureEvidence = {
      kind: dbLabel ? 'classification-rule' : 'image-declaration',
      source: tech.source,
      rule: dbLabel ? RULE_IDS.composeDatabaseImage : RULE_IDS.composeServiceImage,
      description:
        `Compose service "${scope.name}" in ${tech.source} uses image ${reference}` +
        (dbLabel ? `; the image repository is a known ${dbLabel} image.` : '.'),
      detail,
    };
    b.upsertComponent({
      id,
      type: dbLabel ? 'Database' : 'Container',
      name: scope.name,
      certainty: dbLabel ? 'inferred' : 'declared',
      evidence: [evidence],
      technologies: [imageTech],
      uncertainty: [
        dbLabel
          ? 'Whether and how the application connects to this service is not determined; no connection evidence exists in the scanned files.'
          : 'The role of this service in the system is not determined from its image name.',
        ...variableNote,
        ...placementNote,
      ],
      containerRole: 'compose-service',
    });
    b.relate('declares-service', unitId, id, [evidence], `${b.nameOf(unitId)} declares compose service "${scope.name}".`);
    return;
  }

  const id = `image:${tech.source}|${reference}`;
  const evidence: ArchitectureEvidence = {
    kind: 'image-declaration',
    source: tech.source,
    rule: RULE_IDS.dockerfileBaseImage,
    description: `${tech.source} builds FROM ${reference}${scope.index > 0 ? ` (build stage ${scope.index})` : ''}.`,
    detail,
  };
  b.upsertComponent({
    id,
    type: 'Container',
    name: reference,
    certainty: 'declared',
    evidence: [evidence],
    technologies: [imageTech],
    uncertainty: [
      'A build-time base image declared in a Dockerfile; this is not evidence of a running service.',
      ...variableNote,
      ...placementNote,
    ],
    containerRole: 'build-base-image',
  });
  b.relate('builds-on-image', unitId, id, [evidence], `${b.nameOf(unitId)} builds on image ${reference}.`);
}

/* ================================ builder ================================ */

interface ComponentSpec {
  id: string;
  type: ComponentType;
  name: string;
  certainty: Certainty;
  evidence: ArchitectureEvidence[];
  technologies?: ComponentTechnology[];
  uncertainty?: string[];
  ecosystems?: Ecosystem[];
  containerRole?: ContainerRole;
}

class ModelBuilder {
  private readonly componentMap = new Map<string, ArchitectureComponent>();
  private readonly relationshipMap = new Map<string, ArchitectureRelationship>();

  /** Create the component, or merge evidence/technologies/uncertainty into the existing one with the same id. */
  upsertComponent(spec: ComponentSpec): void {
    const existing = this.componentMap.get(spec.id);
    if (!existing) {
      this.componentMap.set(spec.id, {
        id: spec.id,
        type: spec.type,
        name: spec.name,
        certainty: spec.certainty,
        evidence: [...spec.evidence],
        technologies: [...(spec.technologies ?? [])],
        uncertainty: [...(spec.uncertainty ?? [])],
        ...(spec.ecosystems ? { ecosystems: [...spec.ecosystems] } : {}),
        ...(spec.containerRole ? { containerRole: spec.containerRole } : {}),
      });
      return;
    }
    mergeUnique(existing.evidence, spec.evidence);
    mergeUnique(existing.technologies, spec.technologies ?? []);
    mergeUnique(existing.uncertainty, spec.uncertainty ?? []);
  }

  /** Add evidence/technologies to a component that must already exist. */
  enrich(id: string, additions: { evidence?: ArchitectureEvidence[]; technologies?: ComponentTechnology[] }): void {
    const c = this.componentMap.get(id);
    if (!c) {
      throw new Error(`Internal error: component ${id} does not exist`);
    }
    mergeUnique(c.evidence, additions.evidence ?? []);
    mergeUnique(c.technologies, additions.technologies ?? []);
  }

  addUncertainty(componentId: string, text: string): void {
    const c = this.componentMap.get(componentId);
    if (c) mergeUnique(c.uncertainty, [text]);
  }

  /** Create the relationship, or add evidence to the identical existing one. */
  relate(type: RelationshipType, sourceId: string, targetId: string, evidence: ArchitectureEvidence[], description: string): void {
    const id = `rel:${type}|${sourceId}|${targetId}`;
    const existing = this.relationshipMap.get(id);
    if (existing) {
      mergeUnique(existing.evidence, evidence);
      return;
    }
    this.relationshipMap.set(id, { id, type, sourceId, targetId, description, evidence: [...evidence] });
  }

  nameOf(id: string): string {
    return this.componentMap.get(id)?.name ?? id;
  }

  components(): ArchitectureComponent[] {
    return [...this.componentMap.values()];
  }

  relationships(): ArchitectureRelationship[] {
    return [...this.relationshipMap.values()];
  }
}

/* ================================ helpers ================================ */

function dependencyEvidence(
  dep: DetectedDependency,
  rule: string,
  kind: ArchitectureEvidence['kind'],
  description: string
): ArchitectureEvidence {
  return {
    kind,
    source: dep.source,
    rule,
    description,
    detail: { name: dep.name, version: dep.version, category: dep.category },
  };
}

function dependencyTechnology(dep: DetectedDependency): ComponentTechnology {
  return {
    name: dep.name,
    version: dep.version, // exactly as declared
    ecosystem: dep.ecosystem,
    kind: 'dependency',
    category: dep.category,
    source: dep.source,
    ...(dep.resolvedVersion !== undefined ? { resolvedVersion: dep.resolvedVersion } : {}),
    ...(dep.notes ? { notes: dep.notes } : {}),
  };
}

function mergeUnique<T>(target: T[], additions: readonly T[]): void {
  const seen = new Set(target.map((x) => JSON.stringify(x)));
  for (const item of additions) {
    const key = JSON.stringify(item);
    if (!seen.has(key)) {
      seen.add(key);
      target.push(item);
    }
  }
}

function unique<T>(items: readonly T[]): T[] {
  return [...new Set(items)];
}

function appId(unit: string): string {
  return `app:${unit === '' ? '.' : unit}`;
}

function display(version: string | null): string {
  return version === null ? '(no version declared)' : version === '' ? '(empty)' : version;
}

function dirName(relPath: string): string {
  const i = relPath.lastIndexOf('/');
  return i === -1 ? '' : relPath.slice(0, i);
}

function baseName(relPath: string): string {
  return relPath.slice(relPath.lastIndexOf('/') + 1);
}

function isDockerFile(name: string): boolean {
  return name === 'Dockerfile' || /^(docker-compose|compose)\.ya?ml$/.test(name);
}

/** Root first, then shallower before deeper, then alphabetical: deterministic. */
function compareUnits(a: string, b: string): number {
  const depth = (u: string): number => (u === '' ? 0 : u.split('/').length);
  return depth(a) - depth(b) || (a < b ? -1 : a > b ? 1 : 0);
}

/** Closest ancestor-or-self directory that is a project unit; the root ('') always is. */
function nearestUnit(unitDirs: ReadonlySet<string>, dir: string): string {
  let current = dir;
  while (current !== '' && !unitDirs.has(current)) {
    current = dirName(current);
  }
  return current;
}
