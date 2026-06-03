import { featureFlags } from "./feature-flags.js";
import type { FeatureName } from "./feature-flags.js";

/** An MCP tool definition exposed by the BioMCP server. */
export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
}

const toolDefinitions: Record<string, ToolDefinition> = {
  search_pubmed: {
    name: "search_pubmed",
    description: "Search PubMed for biomedical literature",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query" },
        limit: { type: "number", description: "Number of results (1-100)", default: 10 },
        sort: { type: "string", enum: ["relevance", "publication_date", "first_author"], default: "relevance" },
        filters: {
          type: "object",
          properties: {
            publication_date_start: { type: "string", description: "Start date (YYYY-MM-DD)" },
            publication_date_end: { type: "string", description: "End date (YYYY-MM-DD)" },
            journal: { type: "string", description: "Journal name filter" },
            author: { type: "string", description: "Author name filter" },
            article_type: { type: "array", items: { type: "string" }, description: "Article types" },
          },
        },
      },
      required: ["query"],
    },
  },
  get_citation_network: {
    name: "get_citation_network",
    description: "Get citation network for a PubMed article",
    inputSchema: {
      type: "object",
      properties: {
        pmid: { type: "string", description: "PubMed ID" },
        depth: { type: "number", description: "Citation depth (1-3)", default: 1 },
      },
      required: ["pmid"],
    },
  },
  lookup_variant: {
    name: "lookup_variant",
    description: "Look up variant information from dbSNP and ClinVar",
    inputSchema: {
      type: "object",
      properties: {
        identifier: { type: "string", description: "Variant identifier (rs number, chr:pos, etc.)" },
        includeFrequencies: { type: "boolean", description: "Include population frequencies", default: true },
        includeConsequences: { type: "boolean", description: "Include functional consequences", default: true },
        assembly: { type: "string", enum: ["GRCh37", "GRCh38"], default: "GRCh38" },
      },
      required: ["identifier"],
    },
  },
  search_genes: {
    name: "search_genes",
    description: "Search for gene information",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Gene symbol, name, or ID" },
        organism: { type: "string", description: "Organism name", default: "human" },
        includeAliases: { type: "boolean", description: "Include gene aliases", default: true },
        includePathways: { type: "boolean", description: "Include pathway information", default: false },
      },
      required: ["query"],
    },
  },
  get_population_frequency: {
    name: "get_population_frequency",
    description: "Get population frequency data for variants",
    inputSchema: {
      type: "object",
      properties: {
        variant: { type: "string", description: "Variant identifier" },
        populations: { type: "array", items: { type: "string" }, description: "Population codes" },
        assembly: { type: "string", enum: ["GRCh37", "GRCh38"], default: "GRCh38" },
      },
      required: ["variant"],
    },
  },
  search_proteins: {
    name: "search_proteins",
    description: "Search UniProt for protein information",
    inputSchema: {
      type: "object",
      properties: {
        identifier: { type: "string", description: "Protein ID, accession, or name" },
        includeStructures: { type: "boolean", description: "Include PDB structures", default: false },
        includeDomains: { type: "boolean", description: "Include domain information", default: true },
        includePathways: { type: "boolean", description: "Include pathway information", default: false },
      },
      required: ["identifier"],
    },
  },
  analyze_protein_structure: {
    name: "analyze_protein_structure",
    description: "Analyze protein structure from PDB (placeholder implementation)",
    inputSchema: {
      type: "object",
      properties: {
        pdbId: { type: "string", description: "PDB structure identifier" },
        includeMetadata: { type: "boolean", description: "Include structure metadata", default: true },
      },
      required: ["pdbId"],
    },
  },
  interpret_clinical_variant: {
    name: "interpret_clinical_variant",
    description: "Get clinical interpretation of genetic variants",
    inputSchema: {
      type: "object",
      properties: {
        variant: { type: "string", description: "Variant identifier" },
        includeEvidence: { type: "boolean", description: "Include evidence details", default: true },
        assembly: { type: "string", enum: ["GRCh37", "GRCh38"], default: "GRCh38" },
      },
      required: ["variant"],
    },
  },
  search_omim: {
    name: "search_omim",
    description: "Search OMIM for disease-gene associations (requires API key or placeholder mode)",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Disease name, gene symbol, or OMIM ID" },
        type: { type: "string", enum: ["gene", "disease", "phenotype"], description: "Search type" },
      },
      required: ["query"],
    },
  },
  blast_sequence: {
    name: "blast_sequence",
    description: "Perform BLAST sequence similarity search (placeholder implementation)",
    inputSchema: {
      type: "object",
      properties: {
        sequence: { type: "string", description: "Query sequence (protein or nucleotide)" },
        database: { type: "string", enum: ["nr", "swissprot", "pdb"], default: "nr" },
        program: { type: "string", enum: ["blastp", "blastn", "blastx", "tblastn"], default: "blastp" },
        evalue: { type: "number", description: "E-value threshold", default: 0.001 },
        maxTargets: { type: "number", description: "Maximum number of hits", default: 10 },
      },
      required: ["sequence"],
    },
  },
  align_sequences: {
    name: "align_sequences",
    description: "Perform multiple sequence alignment (placeholder implementation)",
    inputSchema: {
      type: "object",
      properties: {
        sequences: { type: "array", items: { type: "string" }, description: "Input sequences" },
        method: { type: "string", enum: ["clustal", "muscle", "mafft"], default: "clustal" },
      },
      required: ["sequences"],
    },
  },
};
const toolFeatureMap: Record<string, FeatureName> = {
  search_pubmed: "pubmedSearch",
  get_citation_network: "citationNetwork",
  lookup_variant: "variantLookup",
  search_genes: "geneSearch",
  get_population_frequency: "populationFrequency",
  search_proteins: "proteinSearch",
  analyze_protein_structure: "proteinStructure",
  interpret_clinical_variant: "clinicalVariantInterpretation",
  search_omim: "omimSearch",
  blast_sequence: "blastSearch",
  align_sequences: "sequenceAlignment",
};
export function getAvailableTools(): ToolDefinition[] {
  const availableTools: ToolDefinition[] = [];
  for (const [toolName, toolDef] of Object.entries(toolDefinitions)) {
    const featureKey = toolFeatureMap[toolName];
    if (featureKey && featureFlags.isEnabled(featureKey)) {
      availableTools.push(toolDef);
    }
  }
  return availableTools;
}
export function isToolEnabled(toolName: string): boolean {
  const featureKey = toolFeatureMap[toolName];
  return featureKey ? featureFlags.isEnabled(featureKey) : false;
}
