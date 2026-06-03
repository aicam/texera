import { BaseApiClient } from "./base-client.js";

/** Per-variant population frequency record returned by Ensembl. */
export interface EnsemblPopulation {
  [key: string]: unknown;
}

/** Variation payload returned by the Ensembl `variation/human/{id}` endpoint. */
export interface EnsemblVariation {
  populations?: EnsemblPopulation[];
  [key: string]: unknown;
}

/** Options accepted by {@link EnsemblClient.performVEP}. */
export interface VEPOptions {
  [key: string]: unknown;
}

export class EnsemblClient extends BaseApiClient {
  constructor() {
    super({
      baseUrl: "https://rest.ensembl.org/",
      rateLimiter: {
        points: 15,
        duration: 1,
      },
      timeout: 30000,
    });
  }
  async lookupVariant(variantId: string, expand?: string[]): Promise<unknown> {
    const params: Record<string, string> = {
      content_type: "application/json",
    };
    if (expand && expand.length > 0) {
      params.expand = expand.join(",");
    }
    const response = await this.makeRequest<unknown>(`variation/human/${encodeURIComponent(variantId)}`, { params });
    if (!response.success || !response.data) {
      throw new Error(response.error || `Variant ${variantId} not found`);
    }
    return response.data;
  }
  async lookupGene(geneId: string, expand?: string[]): Promise<unknown> {
    const params: Record<string, string> = {
      content_type: "application/json",
    };
    if (expand && expand.length > 0) {
      params.expand = expand.join(",");
    }
    const response = await this.makeRequest<unknown>(`lookup/id/${encodeURIComponent(geneId)}`, { params });
    if (!response.success || !response.data) {
      throw new Error(response.error || `Gene ${geneId} not found`);
    }
    return response.data;
  }
  async searchGenes(query: string, species: string = "human"): Promise<unknown[]> {
    const params: Record<string, string> = {
      content_type: "application/json",
      species: species === "human" ? "homo_sapiens" : species,
    };
    const response = await this.makeRequest<unknown>(
      `lookup/symbol/${species === "human" ? "homo_sapiens" : species}/${encodeURIComponent(query)}`,
      { params }
    );
    if (!response.success) {
      return this.searchGenesByText(query, species);
    }
    return Array.isArray(response.data) ? response.data : response.data ? [response.data] : [];
  }
  async searchGenesByText(query: string, species: string = "human"): Promise<unknown[]> {
    const params: Record<string, string> = {
      content_type: "application/json",
      species: species === "human" ? "homo_sapiens" : species,
      limit: "20",
    };
    const response = await this.makeRequest<unknown>(
      `lookup/symbol/${species === "human" ? "homo_sapiens" : species}/${encodeURIComponent(query)}`,
      { params }
    );
    if (!response.success || !response.data) {
      return [];
    }
    return Array.isArray(response.data) ? response.data : [response.data];
  }
  async getVariantConsequences(variantId: string): Promise<unknown> {
    const params: Record<string, string> = {
      content_type: "application/json",
    };
    const response = await this.makeRequest<unknown>(`vep/human/id/${encodeURIComponent(variantId)}`, { params });
    if (!response.success || !response.data) {
      throw new Error(response.error || `Failed to get consequences for ${variantId}`);
    }
    return response.data;
  }
  async getVariantFrequencies(variantId: string): Promise<EnsemblPopulation[]> {
    const params: Record<string, string> = {
      content_type: "application/json",
      population_genotypes: "1",
    };
    const response = await this.makeRequest<EnsemblVariation>(`variation/human/${encodeURIComponent(variantId)}`, {
      params,
    });
    if (!response.success || !response.data) {
      throw new Error(response.error || `Failed to get frequencies for ${variantId}`);
    }
    return response.data.populations || [];
  }
  async performVEP(variants: unknown[], options: VEPOptions = {}): Promise<unknown> {
    const params: Record<string, string> = {
      content_type: "application/json",
      ...Object.fromEntries(
        Object.entries(options)
          .filter(([_, value]) => value !== undefined)
          .map(([key, value]) => [key, Array.isArray(value) ? value.join(",") : String(value)])
      ),
    };
    const response = await this.makeRequest<unknown>("vep/human/region", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ variants }),
      params,
    });
    if (!response.success || !response.data) {
      throw new Error(response.error || "VEP analysis failed");
    }
    return response.data;
  }
}
