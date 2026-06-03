import { z } from "zod";
import { UniProtClient } from "../../utils/api-clients/uniprot-client.js";
import { MemoryCache } from "../../utils/cache/memory-cache.js";
import { ProteinSearchSchema } from "../../utils/validation/schemas.js";

export interface ToolTextContent {
  type: "text";
  text: string;
}

export interface ToolResult {
  content: ToolTextContent[];
  isError?: boolean;
}

export interface ProteinInfo {
  uniprotId: string;
  name: string;
  fullName: string;
  organism: string;
  sequence: string;
  length: number;
  function?: string;
  domains?: unknown[];
  structures?: unknown[];
  pathways?: unknown[];
}

export interface UniProtNameValue {
  value: string;
}

export interface UniProtProteinDescription {
  recommendedName?: {
    fullName?: UniProtNameValue;
  };
  alternativeNames?: Array<{
    fullName?: UniProtNameValue;
  }>;
}

export interface UniProtComment {
  commentType: string;
  texts?: UniProtNameValue[];
}

export interface UniProtSearchResponse {
  results: UniProtEntry[];
}

export interface UniProtEntry {
  primaryAccession: string;
  uniProtkbId: string;
  organism?: {
    scientificName?: string;
  };
  sequence?: {
    value?: string;
    length?: number;
  };
  comments?: UniProtComment[];
  proteinDescription?: UniProtProteinDescription;
}

export interface ProteinStructureInfo {
  pdb_id: string;
  title: string;
  method: string;
  resolution: string;
  chains: string[];
  ligands: unknown[];
  notes: string;
  analysis: {
    secondary_structure: {
      alpha_helices: number;
      beta_sheets: number;
      loops: number;
    };
    binding_sites: unknown[];
    domains: unknown[];
  };
  metadata?: {
    deposition_date: string;
    authors: string[];
    citation: string;
  };
}

export interface ProteinStructureArgs {
  pdbId?: unknown;
  includeMetadata?: boolean;
}

export interface ProteinSequenceAnalysis {
  sequence_length: number;
  molecular_weight: number;
  amino_acid_composition: Record<string, number>;
  estimated_isoelectric_point: number;
  hydrophobic_residues: number;
  charged_residues: number;
}

export class ProteinsModule {
  uniprotClient: UniProtClient;
  cache: MemoryCache;
  constructor(cache: MemoryCache) {
    this.uniprotClient = new UniProtClient();
    this.cache = cache;
  }
  async searchProteins(args: unknown): Promise<ToolResult> {
    try {
      const validatedArgs = ProteinSearchSchema.parse(args);
      const cacheKey = this.cache.generateKey(
        "protein_search",
        validatedArgs.identifier,
        String(validatedArgs.includeStructures),
        String(validatedArgs.includeDomains),
        String(validatedArgs.includePathways)
      );
      const cachedResult = this.cache.get<ProteinInfo[]>(cacheKey);
      if (cachedResult) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  proteins: cachedResult,
                  cached: true,
                  query: validatedArgs.identifier,
                },
                null,
                2
              ),
            },
          ],
        };
      }
      const proteins: ProteinInfo[] = [];
      const isAccession = /^[OPQ][0-9][A-Z0-9]{3}[0-9]|[A-NR-Z][0-9]([A-Z][A-Z0-9]{2}[0-9]){1,2}$/.test(
        validatedArgs.identifier
      );
      if (isAccession) {
        try {
          const uniprotEntry = (await this.uniprotClient.getProteinById(
            validatedArgs.identifier
          )) as unknown as UniProtEntry;
          const protein = await this.convertUniProtToProteinInfo(uniprotEntry, validatedArgs);
          proteins.push(protein);
        } catch (error) {
          console.error("Direct UniProt lookup failed:", error);
        }
      } else {
        try {
          const searchResult = (await this.uniprotClient.searchProteins(validatedArgs.identifier, {
            size: 10,
            fields: [
              "accession",
              "id",
              "protein_name",
              "organism_name",
              "length",
              "sequence",
              "gene_names",
              "cc_function",
            ],
          })) as UniProtSearchResponse;
          for (const entry of searchResult.results.slice(0, 5)) {
            const protein = await this.convertUniProtToProteinInfo(entry, validatedArgs);
            proteins.push(protein);
          }
        } catch (error) {
          console.error("UniProt search failed:", error);
        }
      }
      this.cache.set(cacheKey, proteins, 3600000);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                proteins,
                query: validatedArgs.identifier,
                total_results: proteins.length,
                sources: ["UniProt"],
              },
              null,
              2
            ),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error searching proteins: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  async analyzeProteinStructure(args: ProteinStructureArgs): Promise<ToolResult> {
    try {
      const { pdbId, includeMetadata = true } = args;
      if (!pdbId || typeof pdbId !== "string") {
        throw new Error("Valid PDB ID is required");
      }
      const cacheKey = this.cache.generateKey("protein_structure", pdbId, String(includeMetadata));
      const cachedResult = this.cache.get<ProteinStructureInfo>(cacheKey);
      if (cachedResult) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  ...cachedResult,
                  cached: true,
                },
                null,
                2
              ),
            },
          ],
        };
      }
      const structureInfo: ProteinStructureInfo = {
        pdb_id: pdbId.toUpperCase(),
        title: `Structure analysis for ${pdbId.toUpperCase()}`,
        method: "X-ray crystallography",
        resolution: "2.5 Å",
        chains: ["A", "B"],
        ligands: [],
        notes:
          "This is a placeholder implementation. Full PDB integration would provide detailed structural information.",
        analysis: {
          secondary_structure: {
            alpha_helices: 8,
            beta_sheets: 12,
            loops: 15,
          },
          binding_sites: [],
          domains: [],
        },
        metadata: includeMetadata
          ? {
              deposition_date: "2023-01-01",
              authors: ["Researcher, A.", "Scientist, B."],
              citation: "Placeholder citation",
            }
          : undefined,
      };
      this.cache.set(cacheKey, structureInfo, 7200000);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(structureInfo, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error analyzing protein structure: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  async convertUniProtToProteinInfo(
    uniprotEntry: UniProtEntry,
    options: z.infer<typeof ProteinSearchSchema>
  ): Promise<ProteinInfo> {
    const proteinInfo: ProteinInfo = {
      uniprotId: uniprotEntry.primaryAccession,
      name: uniprotEntry.uniProtkbId,
      fullName: this.extractProteinName(uniprotEntry),
      organism: uniprotEntry.organism?.scientificName || "Unknown",
      sequence: uniprotEntry.sequence?.value || "",
      length: uniprotEntry.sequence?.length || 0,
    };
    const functionComment = uniprotEntry.comments?.find((c) => c.commentType === "FUNCTION");
    if (functionComment?.texts?.[0]?.value) {
      proteinInfo.function = functionComment.texts[0].value;
    }
    if (options.includeDomains) {
      try {
        proteinInfo.domains = await this.uniprotClient.getProteinDomains(uniprotEntry.primaryAccession);
      } catch (error) {
        console.error("Failed to get protein domains:", error);
        proteinInfo.domains = [];
      }
    }
    if (options.includeStructures) {
      try {
        proteinInfo.structures = await this.uniprotClient.getProteinStructures(uniprotEntry.primaryAccession);
      } catch (error) {
        console.error("Failed to get protein structures:", error);
        proteinInfo.structures = [];
      }
    }
    if (options.includePathways) {
      try {
        proteinInfo.pathways = await this.uniprotClient.getProteinPathways(uniprotEntry.primaryAccession);
      } catch (error) {
        console.error("Failed to get protein pathways:", error);
        proteinInfo.pathways = [];
      }
    }
    return proteinInfo;
  }
  extractProteinName(uniprotEntry: UniProtEntry): string {
    const proteinDescription = uniprotEntry.proteinDescription;
    if (proteinDescription?.recommendedName?.fullName?.value) {
      return proteinDescription.recommendedName.fullName.value;
    }
    if (proteinDescription?.alternativeNames?.[0]?.fullName?.value) {
      return proteinDescription.alternativeNames[0].fullName.value;
    }
    return uniprotEntry.uniProtkbId || "Unknown protein";
  }
  async getProteinInteractions(accession: string): Promise<unknown> {
    return {
      protein_accession: accession,
      interactions: [],
      note: "Protein interaction data integration not yet implemented",
    };
  }
  async analyzeProteinSequence(sequence: string): Promise<ProteinSequenceAnalysis> {
    const length = sequence.length;
    const aminoAcidComposition: Record<string, number> = {};
    for (const aa of sequence) {
      aminoAcidComposition[aa] = (aminoAcidComposition[aa] || 0) + 1;
    }
    const aaWeights: Record<string, number> = {
      A: 89.1,
      R: 174.2,
      N: 132.1,
      D: 133.1,
      C: 121.2,
      E: 147.1,
      Q: 146.2,
      G: 75.1,
      H: 155.2,
      I: 131.2,
      L: 131.2,
      K: 146.2,
      M: 149.2,
      F: 165.2,
      P: 115.1,
      S: 105.1,
      T: 119.1,
      W: 204.2,
      Y: 181.2,
      V: 117.1,
    };
    let molecularWeight = 0;
    for (const [aa, count] of Object.entries(aminoAcidComposition)) {
      molecularWeight += (aaWeights[aa] || 0) * count;
    }
    let charge = 0;
    const pKa: Record<string, number> = {
      D: 3.9,
      E: 4.3,
      C: 8.3,
      Y: 10.1,
      H: 6.0,
      K: 10.5,
      R: 12.5,
    };
    for (const [aa, count] of Object.entries(aminoAcidComposition)) {
      if (pKa[aa]) {
        if (["D", "E"].includes(aa)) {
          charge -= count;
        } else {
          charge += count;
        }
      }
    }
    const estimatedPI = charge > 0 ? 8.5 : 5.5;
    return {
      sequence_length: length,
      molecular_weight: Math.round(molecularWeight),
      amino_acid_composition: aminoAcidComposition,
      estimated_isoelectric_point: estimatedPI,
      hydrophobic_residues:
        (aminoAcidComposition["A"] || 0) +
        (aminoAcidComposition["I"] || 0) +
        (aminoAcidComposition["L"] || 0) +
        (aminoAcidComposition["V"] || 0) +
        (aminoAcidComposition["F"] || 0) +
        (aminoAcidComposition["W"] || 0) +
        (aminoAcidComposition["Y"] || 0),
      charged_residues:
        (aminoAcidComposition["D"] || 0) +
        (aminoAcidComposition["E"] || 0) +
        (aminoAcidComposition["K"] || 0) +
        (aminoAcidComposition["R"] || 0),
    };
  }
}
