import { Ecosystem } from '../scanner/technology/types';

/**
 * V0.4 — Structured Security Architecture Model.
 *
 * A deterministic, evidence-backed description of what the scanned files DECLARE.
 * It is not a runtime model: nothing here asserts network traffic, API calls,
 * deployment topology or trust boundaries. Every element carries the evidence
 * (file + rule) that produced it so later milestones can trace findings back to it.
 */

export const COMPONENT_TYPES = [
  'Application',
  'Frontend',
  'Backend',
  'Database',
  'External Service',
  'Container',
  'Library/Dependency',
  'Unknown',
] as const;
export type ComponentType = (typeof COMPONENT_TYPES)[number];

/**
 * What a relationship states. All of them are DECLARATION relationships, i.e. "file X says so".
 * None of them implies that two things communicate at runtime.
 *
 *  contains            parent -> child     child is part of / located inside the parent (structure or framework use)
 *  declares-dependency application -> lib  a manifest of the application lists the library
 *  builds-on-image     application -> img  a Dockerfile of the application starts FROM the image
 *  declares-service    application -> svc  a compose file of the application defines the service
 *  built-with          component -> lib    the component was identified from this library (classification evidence)
 *  client-library-for  library -> target   the library is a known client/SDK for the database or external service
 */
export const RELATIONSHIP_TYPES = [
  'contains',
  'declares-dependency',
  'builds-on-image',
  'declares-service',
  'built-with',
  'client-library-for',
] as const;
export type RelationshipType = (typeof RELATIONSHIP_TYPES)[number];

/**
 * How firmly the component's TYPE is established:
 *  declared  the file itself states it (a dependency is a library; a Dockerfile FROM is a container image)
 *  inferred  a deterministic rule classified it (e.g. "express" => Backend); plausible, not proven
 *  unknown   evidence is insufficient to decide the role
 */
export type Certainty = 'declared' | 'inferred' | 'unknown';

export type EvidenceKind =
  | 'workspace-scan' // V0.2 scan facts
  | 'manifest-file' // existence/location of a manifest
  | 'dependency-declaration' // a dependency listed in a manifest
  | 'technology-declaration' // a runtime/platform declared in a manifest (engines.node, go directive, ...)
  | 'image-declaration' // an image listed in a Dockerfile / compose file
  | 'classification-rule'; // a deterministic rule applied to a declaration

export interface ArchitectureEvidence {
  kind: EvidenceKind;
  /** Workspace-relative POSIX path of the file the evidence comes from ('.' = the workspace itself). */
  source: string;
  /** Identifier of the detection rule (see RULE_IDS). */
  rule: string;
  /** Human-readable explanation. Contains names/versions/paths only, never file contents or values. */
  description: string;
  /** The declared facts the rule looked at, exactly as written. */
  detail?: {
    name?: string;
    version?: string | null;
    category?: string;
    reference?: string;
  };
}

export interface ComponentTechnology {
  name: string;
  /** Declared version / range / tag EXACTLY as written; null if none declared. */
  version: string | null;
  ecosystem: Ecosystem;
  kind: 'dependency' | 'runtime' | 'image';
  category?: string;
  source: string;
  /** Maven only; see V0.3 DetectedDependency.resolvedVersion. */
  resolvedVersion?: string;
  notes?: string;
}

export interface ArchitectureComponent {
  /** Stable within a run, and deterministic: same inputs give the same identifiers. */
  id: string;
  type: ComponentType;
  name: string;
  certainty: Certainty;
  /** Always at least one entry. */
  evidence: ArchitectureEvidence[];
  technologies: ComponentTechnology[];
  /** What the evidence does NOT establish about this component. */
  uncertainty: string[];
  /** Project modules only: ecosystems of the manifests found in this module. */
  ecosystems?: Ecosystem[];
  /**
   * Docker-derived components only. A Dockerfile FROM image is a BUILD-time base image, not a running
   * service; a compose service is a declared (not verified) running service. Later milestones must not
   * treat the former as the latter.
   */
  containerRole?: ContainerRole;
}

export type ContainerRole = 'build-base-image' | 'compose-service';

export interface ArchitectureRelationship {
  /** Stable within a run, deterministic. */
  id: string;
  type: RelationshipType;
  sourceId: string;
  targetId: string;
  description: string;
  /** Always at least one entry. */
  evidence: ArchitectureEvidence[];
}

export interface ArchitectureModel {
  /** Name only. The model never stores absolute local paths, so it can be reported or persisted safely. */
  workspaceName: string;
  components: ArchitectureComponent[];
  relationships: ArchitectureRelationship[];
  /** Problems that make the model incomplete (unreadable manifests, truncated scan, ...). */
  warnings: string[];
}

export interface ArchitectureSummary {
  componentCount: number;
  relationshipCount: number;
  componentsByType: Partial<Record<ComponentType, number>>;
  relationshipsByType: Partial<Record<RelationshipType, number>>;
}
