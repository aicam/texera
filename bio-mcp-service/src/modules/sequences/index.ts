import { MemoryCache } from "../../utils/cache/memory-cache.js";
import { BlastSearchSchema } from "../../utils/validation/schemas.js";

export interface ToolTextContent {
  type: "text";
  text: string;
}

export interface ToolResult {
  content: ToolTextContent[];
  isError?: boolean;
}

export interface SequenceHit {
  accession: string;
  description: string;
  eValue: number;
  bitScore: number;
  identity: number;
  coverage: number;
  alignmentLength: number;
}

export interface BlastResult {
  queryId: string;
  hits: SequenceHit[];
}

export interface BlastSearchResult extends BlastResult {
  search_parameters: {
    query_length: number;
    database: string;
    program: string;
    evalue_threshold: number;
    max_targets: number;
  };
  note: string;
}

export interface ValidatedSequence {
  id: string;
  sequence: string;
  length: number;
}

export interface AlignedSequence {
  id: string;
  aligned_sequence: string;
  original_length: number;
  aligned_length: number;
}

export interface AlignmentResult {
  method: string;
  input_sequences: number;
  alignment: {
    aligned_sequences: AlignedSequence[];
    consensus: string;
    conservation_scores: number[];
  };
  statistics: {
    average_identity: number;
    gaps_introduced: number;
    alignment_score: number;
  };
  note: string;
}

export interface AlignSequencesArgs {
  sequences?: string[];
  method?: string;
}

export interface NucleotideComposition {
  A: number;
  T: number;
  C: number;
  G: number;
  N: number;
}

export interface NucleotideCompositionResult {
  sequence_type: "nucleotide";
  length: number;
  composition: NucleotideComposition;
  percentages: {
    A: number;
    T: number;
    C: number;
    G: number;
    N: number;
  };
  gc_content: number;
  at_content: number;
  gc_skew: number;
  at_skew: number;
}

export interface ProteinCompositionResult {
  sequence_type: "protein";
  length: number;
  composition: Record<string, number>;
  classifications: {
    hydrophobic: number;
    polar: number;
    charged: number;
    special: number;
  };
  percentages: {
    hydrophobic: number;
    polar: number;
    charged: number;
    special: number;
  };
}

export class SequencesModule {
  cache: MemoryCache;
  constructor(cache: MemoryCache) {
    this.cache = cache;
  }
  async blastSequence(args: unknown): Promise<ToolResult> {
    try {
      const validatedArgs = BlastSearchSchema.parse(args);
      const cacheKey = this.cache.generateKey(
        "blast_search",
        validatedArgs.sequence,
        validatedArgs.database,
        validatedArgs.program,
        validatedArgs.evalue,
        validatedArgs.maxTargets
      );
      const cachedResult = this.cache.get<BlastSearchResult>(cacheKey);
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
      const cleanSequence = this.validateAndCleanSequence(validatedArgs.sequence, validatedArgs.program);
      const blastResult: BlastResult = {
        queryId: this.generateQueryId(),
        hits: [
          {
            accession: "P12345",
            description: `Example protein match for ${validatedArgs.program} search`,
            eValue: 1e-50,
            bitScore: 250.5,
            identity: 85.2,
            coverage: 92.1,
            alignmentLength: cleanSequence.length,
          },
          {
            accession: "Q67890",
            description: "Another example protein with similarity",
            eValue: 1e-30,
            bitScore: 180.3,
            identity: 78.5,
            coverage: 85.7,
            alignmentLength: Math.floor(cleanSequence.length * 0.8),
          },
          {
            accession: "R11111",
            description: "Third example match with lower similarity",
            eValue: 1e-10,
            bitScore: 120.1,
            identity: 65.3,
            coverage: 70.2,
            alignmentLength: Math.floor(cleanSequence.length * 0.6),
          },
        ],
      };
      const searchResult: BlastSearchResult = {
        ...blastResult,
        search_parameters: {
          query_length: cleanSequence.length,
          database: validatedArgs.database,
          program: validatedArgs.program,
          evalue_threshold: validatedArgs.evalue,
          max_targets: validatedArgs.maxTargets,
        },
        note: "This is a placeholder BLAST implementation. Real implementation would require BLAST+ integration or web service access.",
      };
      this.cache.set(cacheKey, searchResult, 1800000);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(searchResult, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error performing BLAST search: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  async alignSequences(args: AlignSequencesArgs): Promise<ToolResult> {
    try {
      const { sequences, method = "clustal" } = args;
      if (!sequences || !Array.isArray(sequences) || sequences.length < 2) {
        throw new Error("At least 2 sequences are required for alignment");
      }
      if (sequences.length > 100) {
        throw new Error("Maximum 100 sequences allowed for alignment");
      }
      const cacheKey = this.cache.generateKey("sequence_alignment", JSON.stringify(sequences), method);
      const cachedResult = this.cache.get<AlignmentResult>(cacheKey);
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
      const validatedSequences: ValidatedSequence[] = sequences.map((seq, index) => {
        const cleanSeq = seq.replace(/\s/g, "").toUpperCase();
        if (cleanSeq.length < 10) {
          throw new Error(`Sequence ${index + 1} is too short (minimum 10 characters)`);
        }
        return {
          id: `seq_${index + 1}`,
          sequence: cleanSeq,
          length: cleanSeq.length,
        };
      });
      const alignmentResult: AlignmentResult = {
        method,
        input_sequences: validatedSequences.length,
        alignment: {
          aligned_sequences: validatedSequences.map((seq) => ({
            id: seq.id,
            aligned_sequence: seq.sequence,
            original_length: seq.length,
            aligned_length: seq.length,
          })),
          consensus: this.generateConsensus(validatedSequences.map((s) => s.sequence)),
          conservation_scores: [],
        },
        statistics: {
          average_identity: 75.5,
          gaps_introduced: 25,
          alignment_score: 450.2,
        },
        note: "This is a placeholder alignment implementation. Real implementation would require integration with alignment tools like Clustal, MUSCLE, or MAFFT.",
      };
      this.cache.set(cacheKey, alignmentResult, 1800000);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(alignmentResult, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error performing sequence alignment: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  validateAndCleanSequence(sequence: string, program: string): string {
    const cleanSequence = sequence.replace(/\s/g, "").toUpperCase();
    if (cleanSequence.length < 10) {
      throw new Error("Sequence must be at least 10 characters long");
    }
    if (program === "blastn") {
      if (!/^[ATCGNX-]+$/.test(cleanSequence)) {
        throw new Error("Invalid nucleotide sequence. Only A, T, C, G, N, X, and - are allowed.");
      }
    } else {
      if (!/^[ACDEFGHIKLMNPQRSTVWYUX*-]+$/.test(cleanSequence)) {
        throw new Error("Invalid protein sequence. Only standard amino acid codes are allowed.");
      }
    }
    return cleanSequence;
  }
  generateQueryId(): string {
    return `query_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  generateConsensus(sequences: string[]): string {
    if (sequences.length === 0) return "";
    const maxLength = Math.max(...sequences.map((s) => s.length));
    let consensus = "";
    for (let i = 0; i < maxLength; i++) {
      const residues: Record<string, number> = {};
      for (const seq of sequences) {
        if (i < seq.length) {
          const residue = seq[i];
          residues[residue] = (residues[residue] || 0) + 1;
        }
      }
      let mostCommon = "";
      let maxCount = 0;
      for (const [residue, count] of Object.entries(residues)) {
        if (count > maxCount) {
          maxCount = count;
          mostCommon = residue;
        }
      }
      consensus += maxCount > sequences.length / 2 ? mostCommon : "X";
    }
    return consensus;
  }
  async analyzeSequenceComposition(sequence: string): Promise<NucleotideCompositionResult | ProteinCompositionResult> {
    const cleanSequence = sequence.replace(/\s/g, "").toUpperCase();
    const isNucleotide = /^[ATCGN]+$/.test(cleanSequence);
    if (isNucleotide) {
      return this.analyzeNucleotideComposition(cleanSequence);
    } else {
      return this.analyzeProteinComposition(cleanSequence);
    }
  }
  analyzeNucleotideComposition(sequence: string): NucleotideCompositionResult {
    const composition: NucleotideComposition = { A: 0, T: 0, C: 0, G: 0, N: 0 };
    for (const nucleotide of sequence) {
      if (nucleotide in composition) {
        composition[nucleotide as keyof NucleotideComposition]++;
      }
    }
    const seqLength = sequence.length;
    const gcContent = ((composition.G + composition.C) / seqLength) * 100;
    const atContent = ((composition.A + composition.T) / seqLength) * 100;
    return {
      sequence_type: "nucleotide",
      length: seqLength,
      composition,
      percentages: {
        A: (composition.A / seqLength) * 100,
        T: (composition.T / seqLength) * 100,
        C: (composition.C / seqLength) * 100,
        G: (composition.G / seqLength) * 100,
        N: (composition.N / seqLength) * 100,
      },
      gc_content: gcContent,
      at_content: atContent,
      gc_skew: (composition.G - composition.C) / (composition.G + composition.C),
      at_skew: (composition.A - composition.T) / (composition.A + composition.T),
    };
  }
  analyzeProteinComposition(sequence: string): ProteinCompositionResult {
    const composition: Record<string, number> = {};
    for (const aa of sequence) {
      composition[aa] = (composition[aa] || 0) + 1;
    }
    const seqLength = sequence.length;
    const hydrophobic = ["A", "I", "L", "M", "F", "W", "Y", "V"];
    const polar = ["S", "T", "N", "Q"];
    const charged = ["D", "E", "K", "R"];
    const special = ["C", "G", "P", "H"];
    const classifications = {
      hydrophobic: hydrophobic.reduce((sum, aa) => sum + (composition[aa] || 0), 0),
      polar: polar.reduce((sum, aa) => sum + (composition[aa] || 0), 0),
      charged: charged.reduce((sum, aa) => sum + (composition[aa] || 0), 0),
      special: special.reduce((sum, aa) => sum + (composition[aa] || 0), 0),
    };
    return {
      sequence_type: "protein",
      length: seqLength,
      composition,
      classifications,
      percentages: {
        hydrophobic: (classifications.hydrophobic / seqLength) * 100,
        polar: (classifications.polar / seqLength) * 100,
        charged: (classifications.charged / seqLength) * 100,
        special: (classifications.special / seqLength) * 100,
      },
    };
  }
  async findOpenReadingFrames(sequence: string): Promise<unknown> {
    return {
      sequence_length: sequence.length,
      orfs: [],
      note: "ORF finding not yet implemented",
    };
  }
  async predictSecondaryStructure(sequence: string): Promise<unknown> {
    return {
      sequence_length: sequence.length,
      predicted_structure: "",
      confidence_scores: [],
      note: "Secondary structure prediction not yet implemented",
    };
  }
}
