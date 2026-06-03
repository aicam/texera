import { NCBIClient } from "../../utils/api-clients/ncbi-client.js";
import { EnsemblClient } from "../../utils/api-clients/ensembl-client.js";
import { MemoryCache } from "../../utils/cache/memory-cache.js";
import { VariantLookupSchema, GeneSearchSchema } from "../../utils/validation/schemas.js";

export interface ToolTextContent {
  type: "text";
  text: string;
}

export interface ToolResult {
  content: ToolTextContent[];
  isError?: boolean;
}

interface EnsemblTranscriptConsequence {
  gene_symbol: string;
  transcript_id: string;
  consequence_terms: string[];
  impact: string;
  [key: string]: unknown;
}

interface EnsemblFrequencyEntry {
  frequency: number;
  [key: string]: unknown;
}

interface EnsemblColocatedVariant {
  frequencies?: Record<string, EnsemblFrequencyEntry>;
  [key: string]: unknown;
}

interface EnsemblVariantData {
  id?: string;
  chr?: string;
  start?: number;
  alleles?: string[];
  transcript_consequences?: EnsemblTranscriptConsequence[];
  colocated_variants?: EnsemblColocatedVariant[];
  [key: string]: unknown;
}

interface EnsemblGene {
  id: string;
  symbol?: string;
  display_name: string;
  description: string;
  chr: string;
  start: number;
  end: number;
  strand: number;
  synonyms?: string[];
  [key: string]: unknown;
}

interface NcbiGeneRecord {
  symbol: string;
  geneId: string;
  description: string;
  chromosome: string;
  synonyms?: string[];
}

export interface VariantConsequence {
  geneSymbol: string;
  transcript: string;
  consequence: string;
  impact: string;
}

export interface VariantFrequency {
  global?: number;
  african?: number;
  american?: number;
  eastAsian?: number;
  european?: number;
  southAsian?: number;
}

export interface VariantInfo {
  rsid: string;
  chromosome?: string;
  position?: number;
  referenceAllele?: string;
  alternateAllele?: string;
  consequences?: VariantConsequence[];
  frequency?: VariantFrequency;
}

export interface GeneLocation {
  start: number;
  end: number;
  strand: string;
}

export interface GeneInfo {
  symbol: string;
  geneId: string;
  name: string;
  description: string;
  chromosome: string;
  location: GeneLocation;
  ensemblId?: string;
  aliases?: string[];
}

export interface PopulationFrequencyData {
  variant: string;
  assembly: string;
  frequencies: Record<string, number>;
  populations_available: string[];
}

export interface PopulationFrequencyArgs {
  variant?: unknown;
  populations?: string[];
  assembly?: string;
}

export class GenomicsModule {
  ncbiClient: NCBIClient;
  ensemblClient: EnsemblClient;
  cache: MemoryCache;
  constructor(cache: MemoryCache) {
    this.ncbiClient = new NCBIClient();
    this.ensemblClient = new EnsemblClient();
    this.cache = cache;
  }
  async lookupVariant(args: unknown): Promise<ToolResult> {
    try {
      const validatedArgs = VariantLookupSchema.parse(args);
      const cacheKey = this.cache.generateKey(
        "variant_lookup",
        validatedArgs.identifier,
        validatedArgs.assembly,
        String(validatedArgs.includeFrequencies),
        String(validatedArgs.includeConsequences)
      );
      const cachedResult = this.cache.get<VariantInfo>(cacheKey);
      if (cachedResult) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  variant: cachedResult,
                  cached: true,
                },
                null,
                2
              ),
            },
          ],
        };
      }
      let variantInfo: VariantInfo = {
        rsid: validatedArgs.identifier,
      };
      try {
        const ensemblData = (await this.ensemblClient.lookupVariant(validatedArgs.identifier, [
          "transcript_consequences",
          "colocated_variants",
        ])) as EnsemblVariantData;
        variantInfo = {
          rsid: ensemblData.id || validatedArgs.identifier,
          chromosome: ensemblData.chr,
          position: ensemblData.start,
          referenceAllele: ensemblData.alleles?.[0] || "",
          alternateAllele: ensemblData.alleles?.[1] || "",
        };
        if (validatedArgs.includeConsequences && ensemblData.transcript_consequences) {
          variantInfo.consequences = ensemblData.transcript_consequences.map((tc) => ({
            geneSymbol: tc.gene_symbol,
            transcript: tc.transcript_id,
            consequence: tc.consequence_terms.join(", "),
            impact: tc.impact,
          }));
        }
        if (validatedArgs.includeFrequencies && ensemblData.colocated_variants) {
          const freqData = ensemblData.colocated_variants[0]?.frequencies;
          if (freqData) {
            variantInfo.frequency = {
              global: freqData["1000GENOMES:phase_3:ALL"]?.frequency,
              african: freqData["1000GENOMES:phase_3:AFR"]?.frequency,
              american: freqData["1000GENOMES:phase_3:AMR"]?.frequency,
              eastAsian: freqData["1000GENOMES:phase_3:EAS"]?.frequency,
              european: freqData["1000GENOMES:phase_3:EUR"]?.frequency,
              southAsian: freqData["1000GENOMES:phase_3:SAS"]?.frequency,
            };
          }
        }
      } catch (ensemblError) {
        console.error("Ensembl lookup failed:", ensemblError);
      }
      if (!variantInfo.chromosome || !variantInfo.position) {
        console.warn("Limited variant information available");
      }
      this.cache.set(cacheKey, variantInfo, 3600000);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                variant: variantInfo,
                sources: ["Ensembl"],
                assembly: validatedArgs.assembly,
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
            text: `Error looking up variant: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  async searchGenes(args: unknown): Promise<ToolResult> {
    try {
      const validatedArgs = GeneSearchSchema.parse(args);
      const cacheKey = this.cache.generateKey(
        "gene_search",
        validatedArgs.query,
        validatedArgs.organism,
        String(validatedArgs.includeAliases),
        String(validatedArgs.includePathways)
      );
      const cachedResult = this.cache.get<GeneInfo[]>(cacheKey);
      if (cachedResult) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  genes: cachedResult,
                  cached: true,
                  query: validatedArgs.query,
                  organism: validatedArgs.organism,
                },
                null,
                2
              ),
            },
          ],
        };
      }
      const genes: GeneInfo[] = [];
      if (validatedArgs.organism === "human") {
        try {
          const ensemblGenes = (await this.ensemblClient.searchGenes(validatedArgs.query)) as EnsemblGene[];
          for (const ensemblGene of ensemblGenes) {
            const geneInfo: GeneInfo = {
              symbol: ensemblGene.symbol || ensemblGene.display_name,
              geneId: ensemblGene.id,
              name: ensemblGene.display_name,
              description: ensemblGene.description,
              chromosome: ensemblGene.chr,
              location: {
                start: ensemblGene.start,
                end: ensemblGene.end,
                strand: ensemblGene.strand === 1 ? "+" : "-",
              },
              ensemblId: ensemblGene.id,
            };
            if (validatedArgs.includeAliases) {
              geneInfo.aliases = ensemblGene.synonyms || [];
            }
            genes.push(geneInfo);
          }
        } catch (ensemblError) {
          console.error("Ensembl gene search failed:", ensemblError);
        }
      }
      try {
        const ncbiResult = await this.ncbiClient.searchGene(validatedArgs.query, validatedArgs.organism);
        if (ncbiResult.idList.length > 0) {
          const ncbiGenes = (await this.ncbiClient.fetchGeneDetails(
            ncbiResult.idList.slice(0, 5)
          )) as unknown as NcbiGeneRecord[];
          for (const ncbiGene of ncbiGenes) {
            const existingGene = genes.find(
              (g) => g.symbol.toLowerCase() === ncbiGene.symbol.toLowerCase() || g.geneId === ncbiGene.geneId
            );
            if (!existingGene) {
              const geneInfo: GeneInfo = {
                symbol: ncbiGene.symbol,
                geneId: ncbiGene.geneId,
                name: ncbiGene.symbol,
                description: ncbiGene.description,
                chromosome: ncbiGene.chromosome,
                location: {
                  start: 0,
                  end: 0,
                  strand: "+",
                },
              };
              if (validatedArgs.includeAliases) {
                geneInfo.aliases = ncbiGene.synonyms || [];
              }
              genes.push(geneInfo);
            } else {
              if (ncbiGene.description && existingGene.description !== ncbiGene.description) {
                existingGene.description = `${existingGene.description} | ${ncbiGene.description}`;
              }
              if (ncbiGene.synonyms && validatedArgs.includeAliases) {
                existingGene.aliases = [...(existingGene.aliases || []), ...ncbiGene.synonyms];
              }
            }
          }
        }
      } catch (ncbiError) {
        console.error("NCBI gene search failed:", ncbiError);
      }
      if (validatedArgs.includePathways) {
        console.warn("Pathway information not yet implemented");
      }
      this.cache.set(cacheKey, genes, 3600000);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                genes,
                query: validatedArgs.query,
                organism: validatedArgs.organism,
                total_results: genes.length,
                sources: ["Ensembl", "NCBI Gene"],
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
            text: `Error searching genes: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  async getPopulationFrequency(args: PopulationFrequencyArgs): Promise<ToolResult> {
    try {
      const { variant, populations, assembly = "GRCh38" } = args;
      if (!variant || typeof variant !== "string") {
        throw new Error("Valid variant identifier is required");
      }
      const cacheKey = this.cache.generateKey(
        "population_frequency",
        variant,
        JSON.stringify(populations || []),
        assembly
      );
      const cachedResult = this.cache.get<PopulationFrequencyData>(cacheKey);
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
      try {
        const variantData = (await this.ensemblClient.lookupVariant(variant, [
          "colocated_variants",
        ])) as EnsemblVariantData;
        const frequencyData: PopulationFrequencyData = {
          variant,
          assembly,
          frequencies: {},
          populations_available: [],
        };
        if (variantData.colocated_variants && variantData.colocated_variants[0]?.frequencies) {
          const freqs = variantData.colocated_variants[0].frequencies;
          const populationMap: Record<string, string> = {
            ALL: "1000GENOMES:phase_3:ALL",
            AFR: "1000GENOMES:phase_3:AFR",
            AMR: "1000GENOMES:phase_3:AMR",
            EAS: "1000GENOMES:phase_3:EAS",
            EUR: "1000GENOMES:phase_3:EUR",
            SAS: "1000GENOMES:phase_3:SAS",
          };
          for (const [popCode, ensemblKey] of Object.entries(populationMap)) {
            if (freqs[ensemblKey]) {
              frequencyData.frequencies[popCode] = freqs[ensemblKey].frequency;
              frequencyData.populations_available.push(popCode);
            }
          }
          if (populations && populations.length > 0) {
            const filteredFreqs: Record<string, number> = {};
            for (const pop of populations) {
              if (frequencyData.frequencies[pop.toUpperCase()]) {
                filteredFreqs[pop.toUpperCase()] = frequencyData.frequencies[pop.toUpperCase()];
              }
            }
            frequencyData.frequencies = filteredFreqs;
          }
        }
        this.cache.set(cacheKey, frequencyData, 3600000);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(frequencyData, null, 2),
            },
          ],
        };
      } catch (error) {
        throw new Error(`Failed to get population frequencies: ${error}`);
      }
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error getting population frequency: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  async getVariantConsequences(variant: string, assembly: string = "GRCh38"): Promise<unknown> {
    const cacheKey = this.cache.generateKey("variant_consequences", variant, assembly);
    const cachedResult = this.cache.get<unknown>(cacheKey);
    if (cachedResult) {
      return cachedResult;
    }
    try {
      const consequences = await this.ensemblClient.getVariantConsequences(variant);
      this.cache.set(cacheKey, consequences, 3600000);
      return consequences;
    } catch (error) {
      throw new Error(`Failed to get variant consequences: ${error}`);
    }
  }
  async getGeneRegulation(geneId: string): Promise<unknown> {
    return {
      gene_id: geneId,
      regulatory_elements: [],
      expression_data: {},
      note: "Regulatory data integration not yet implemented",
    };
  }
}
