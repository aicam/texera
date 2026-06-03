/** Boolean availability map for every BioMCP feature. */
export interface FeatureFlags {
  pubmedSearch: boolean;
  citationNetwork: boolean;
  variantLookup: boolean;
  geneSearch: boolean;
  populationFrequency: boolean;
  proteinSearch: boolean;
  proteinStructure: boolean;
  clinicalVariantInterpretation: boolean;
  omimSearch: boolean;
  pharmacogenomics: boolean;
  blastSearch: boolean;
  sequenceAlignment: boolean;
}

/** Identifier of an individual feature flag. */
export type FeatureName = keyof FeatureFlags;

/** Availability descriptor for a tool, optionally with a reason it's disabled. */
export interface AvailableTool {
  name: string;
  enabled: boolean;
  reason?: string;
}

export class FeatureFlagManager {
  flags: FeatureFlags;
  constructor() {
    this.flags = this.determineAvailableFeatures();
  }
  determineAvailableFeatures(): FeatureFlags {
    const hasOMIMKey = !!process.env.OMIM_API_KEY;
    const enablePlaceholderTools = process.env.ENABLE_PLACEHOLDER_TOOLS === "true";
    const enableOMIMPlaceholder = process.env.ENABLE_OMIM_PLACEHOLDER === "true";
    const enableBLASTPlaceholder = process.env.ENABLE_BLAST_PLACEHOLDER === "true";
    return {
      pubmedSearch: true,
      citationNetwork: true,
      variantLookup: true,
      geneSearch: true,
      populationFrequency: true,
      proteinSearch: true,
      proteinStructure: enablePlaceholderTools,
      clinicalVariantInterpretation: true,
      omimSearch: hasOMIMKey || enableOMIMPlaceholder,
      pharmacogenomics: false,
      blastSearch: enableBLASTPlaceholder,
      sequenceAlignment: enablePlaceholderTools,
    };
  }
  getFlags(): FeatureFlags {
    return { ...this.flags };
  }
  isEnabled(feature: FeatureName): boolean {
    return this.flags[feature];
  }
  getAvailableTools(): AvailableTool[] {
    return [
      {
        name: "search_pubmed",
        enabled: this.flags.pubmedSearch,
      },
      {
        name: "get_citation_network",
        enabled: this.flags.citationNetwork,
      },
      {
        name: "lookup_variant",
        enabled: this.flags.variantLookup,
      },
      {
        name: "search_genes",
        enabled: this.flags.geneSearch,
      },
      {
        name: "get_population_frequency",
        enabled: this.flags.populationFrequency,
      },
      {
        name: "search_proteins",
        enabled: this.flags.proteinSearch,
      },
      {
        name: "analyze_protein_structure",
        enabled: this.flags.proteinStructure,
        ...(this.flags.proteinStructure ? {} : { reason: "Requires ENABLE_PLACEHOLDER_TOOLS=true" }),
      },
      {
        name: "interpret_clinical_variant",
        enabled: this.flags.clinicalVariantInterpretation,
      },
      {
        name: "search_omim",
        enabled: this.flags.omimSearch,
        ...(this.flags.omimSearch ? {} : { reason: "Requires OMIM_API_KEY or ENABLE_OMIM_PLACEHOLDER=true" }),
      },
      {
        name: "blast_sequence",
        enabled: this.flags.blastSearch,
        ...(this.flags.blastSearch ? {} : { reason: "Requires ENABLE_BLAST_PLACEHOLDER=true" }),
      },
      {
        name: "align_sequences",
        enabled: this.flags.sequenceAlignment,
        ...(this.flags.sequenceAlignment ? {} : { reason: "Requires ENABLE_PLACEHOLDER_TOOLS=true" }),
      },
    ];
  }
  logConfiguration(): void {
    const available = this.getAvailableTools();
    const enabled = available.filter((tool) => tool.enabled);
    const disabled = available.filter((tool) => !tool.enabled);
    console.error(`🧬 BioMCP Feature Configuration:`);
    console.error(`✅ Enabled tools (${enabled.length}): ${enabled.map((t) => t.name).join(", ")}`);
    if (disabled.length > 0) {
      console.error(`❌ Disabled tools (${disabled.length}): ${disabled.map((t) => t.name).join(", ")}`);
      console.error(`💡 To enable more tools, set these environment variables:`);
      if (disabled.some((t) => t.reason?.includes("OMIM_API_KEY"))) {
        console.error(`   - OMIM_API_KEY=your_key or ENABLE_OMIM_PLACEHOLDER=true`);
      }
      if (disabled.some((t) => t.reason?.includes("PLACEHOLDER_TOOLS"))) {
        console.error(`   - ENABLE_PLACEHOLDER_TOOLS=true`);
      }
      if (disabled.some((t) => t.reason?.includes("BLAST_PLACEHOLDER"))) {
        console.error(`   - ENABLE_BLAST_PLACEHOLDER=true`);
      }
    }
  }
}
export const featureFlags = new FeatureFlagManager();
