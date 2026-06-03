import { z } from "zod";

export const PubMedSearchSchema = z.object({
  query: z.string().min(1, "Query cannot be empty"),
  limit: z.number().int().min(1).max(100).optional().default(10),
  sort: z.enum(["relevance", "publication_date", "first_author"]).optional().default("relevance"),
  filters: z
    .object({
      publication_date_start: z.string().optional(),
      publication_date_end: z.string().optional(),
      journal: z.string().optional(),
      author: z.string().optional(),
      article_type: z.array(z.string()).optional(),
    })
    .optional(),
});

export const VariantLookupSchema = z.object({
  identifier: z.string().min(1, "Variant identifier cannot be empty"),
  includeFrequencies: z.boolean().optional().default(true),
  includeConsequences: z.boolean().optional().default(true),
  assembly: z.enum(["GRCh37", "GRCh38"]).optional().default("GRCh38"),
});

export const GeneSearchSchema = z.object({
  query: z.string().min(1, "Gene query cannot be empty"),
  organism: z.string().optional().default("human"),
  includeAliases: z.boolean().optional().default(true),
  includePathways: z.boolean().optional().default(false),
});

export const ProteinSearchSchema = z.object({
  identifier: z.string().min(1, "Protein identifier cannot be empty"),
  includeStructures: z.boolean().optional().default(false),
  includeDomains: z.boolean().optional().default(true),
  includePathways: z.boolean().optional().default(false),
});

export const BlastSearchSchema = z.object({
  sequence: z.string().min(10, "Sequence must be at least 10 characters"),
  database: z.enum(["nr", "swissprot", "pdb"]).optional().default("nr"),
  program: z.enum(["blastp", "blastn", "blastx", "tblastn"]).optional().default("blastp"),
  evalue: z.number().positive().optional().default(0.001),
  maxTargets: z.number().int().min(1).max(100).optional().default(10),
});

export const ClinicalVariantSchema = z.object({
  variant: z.string().min(1, "Variant identifier cannot be empty"),
  includeEvidence: z.boolean().optional().default(true),
  assembly: z.enum(["GRCh37", "GRCh38"]).optional().default("GRCh38"),
});
