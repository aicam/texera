import { BaseApiClient } from "./base-client.js";

/** Options accepted by {@link UniProtClient.searchProteins}. */
export interface UniProtSearchOptions {
  format?: string;
  size?: number;
  fields?: string[];
  sort?: string;
  facets?: string[];
}

/** A cross-reference entry attached to a UniProt protein. */
export interface UniProtDbReference {
  type: string;
  id: string;
  properties?: {
    Method?: string;
    Resolution?: string;
    Chains?: string;
    [key: string]: unknown;
  };
}

/** A sequence feature attached to a UniProt protein. */
export interface UniProtFeature {
  type: string;
  description?: string;
  location: {
    start: { value: number };
    end: { value: number };
  };
  [key: string]: unknown;
}

/** A UniProt protein entry (subset of fields referenced by this client). */
export interface UniProtProtein {
  dbReferences?: UniProtDbReference[];
  features?: UniProtFeature[];
  [key: string]: unknown;
}

/** Result envelope returned by UniProt id-mapping. */
export interface UniProtIdMappingResponse {
  results: Array<{
    from: string;
    to: { primaryAccession: string };
  }>;
}

/** Mapped id pair produced by {@link UniProtClient.mapIds}. */
export interface IdMapping {
  from: string;
  to: string;
}

/** PDB structure summary produced by {@link UniProtClient.getProteinStructures}. */
export interface ProteinStructure {
  pdbId: string;
  method: string;
  resolution: string | null;
  chains: string | null;
}

/** Domain summary produced by {@link UniProtClient.getProteinDomains}. */
export interface ProteinDomain {
  name: string;
  start: number;
  end: number;
  database: string;
}

export class UniProtClient extends BaseApiClient {
  constructor() {
    super({
      baseUrl: "https://rest.uniprot.org/",
      rateLimiter: {
        points: 1,
        duration: 1,
      },
      timeout: 30000,
    });
  }
  async searchProteins(query: string, options: UniProtSearchOptions = {}): Promise<unknown> {
    const params: Record<string, string> = {
      query: encodeURIComponent(query),
      format: options.format || "json",
      size: String(options.size || 25),
    };
    if (options.fields && options.fields.length > 0) {
      params.fields = options.fields.join(",");
    }
    if (options.sort) {
      params.sort = options.sort;
    }
    if (options.facets && options.facets.length > 0) {
      params.facets = options.facets.join(",");
    }
    const response = await this.makeRequest<unknown>("uniprotkb/search", { params });
    if (!response.success || !response.data) {
      throw new Error(response.error || "UniProt search failed");
    }
    return response.data;
  }
  async getProteinById(accession: string, format: string = "json"): Promise<UniProtProtein> {
    const params: Record<string, string> = {
      format,
    };
    const response = await this.makeRequest<UniProtProtein>(`uniprotkb/${encodeURIComponent(accession)}`, { params });
    if (!response.success || !response.data) {
      throw new Error(response.error || `Protein ${accession} not found`);
    }
    return response.data;
  }
  async getProteinFeatures(accession: string): Promise<UniProtFeature[]> {
    const params: Record<string, string> = {
      format: "json",
    };
    const response = await this.makeRequest<UniProtProtein>(`uniprotkb/${encodeURIComponent(accession)}`, { params });
    if (!response.success || !response.data) {
      throw new Error(response.error || `Protein ${accession} not found`);
    }
    return response.data.features || [];
  }
  async mapIds(ids: string[], fromDb: string, toDb: string): Promise<IdMapping[]> {
    const params: Record<string, string> = {
      from: fromDb,
      to: toDb,
      format: "json",
    };
    const response = await this.makeRequest<UniProtIdMappingResponse>("idmapping/run", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `ids=${ids.join(",")}&from=${fromDb}&to=${toDb}`,
      params,
    });
    if (!response.success || !response.data) {
      throw new Error(response.error || "ID mapping failed");
    }
    return response.data.results.map((result) => ({
      from: result.from,
      to: result.to.primaryAccession,
    }));
  }
  async getProteinStructures(accession: string): Promise<ProteinStructure[]> {
    const protein = await this.getProteinById(accession);
    const pdbReferences = protein.dbReferences?.filter((ref) => ref.type === "PDB") || [];
    return pdbReferences.map((ref) => ({
      pdbId: ref.id,
      method: ref.properties?.Method || "Unknown",
      resolution: ref.properties?.Resolution || null,
      chains: ref.properties?.Chains || null,
    }));
  }
  async getProteinPathways(accession: string): Promise<string[]> {
    const protein = await this.getProteinById(accession);
    const pathwayRefs =
      protein.dbReferences?.filter((ref) => ref.type === "KEGG" || ref.type === "Reactome" || ref.type === "BioCyc") ||
      [];
    return pathwayRefs.map((ref) => `${ref.type}:${ref.id}`);
  }
  async getProteinDomains(accession: string): Promise<ProteinDomain[]> {
    const protein = await this.getProteinById(accession);
    const domainFeatures =
      protein.features?.filter((feature) => feature.type === "domain" || feature.type === "region") || [];
    const domainRefs =
      protein.dbReferences?.filter((ref) => ref.type === "InterPro" || ref.type === "Pfam" || ref.type === "PROSITE") ||
      [];
    const domains = domainFeatures.map((feature) => ({
      name: feature.description || "Unknown domain",
      start: feature.location.start.value,
      end: feature.location.end.value,
      database: "UniProt",
    }));
    const referenceDomains = domainRefs.map((ref) => ({
      name: ref.id,
      start: 0,
      end: 0,
      database: ref.type,
    }));
    return [...domains, ...referenceDomains];
  }
}
