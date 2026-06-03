import { BaseApiClient } from "./base-client.js";
import { parseString } from "xml2js";
import { promisify } from "util";

const parseXML = promisify(parseString);

/** Options accepted by {@link NCBIClient.searchPubMed}. */
export interface PubMedSearchOptions {
  retmax?: number;
  retstart?: number;
  sort?: string;
  datetype?: string;
  mindate?: string;
  maxdate?: string;
}

/** Result of a PubMed esearch query. */
export interface PubMedSearchResult {
  idList: string[];
  count: number;
  retMax: number;
  retStart: number;
  queryTranslation?: string;
}

/** Result of a gene esearch query. */
export interface GeneSearchResult {
  idList: string[];
  count: number;
}

/** A single PubMed article parsed from efetch XML. */
export interface PubMedArticle {
  pmid: unknown;
  title: unknown;
  abstract: unknown;
  authors: string[];
  journal: unknown;
  publicationDate: string;
  doi?: string;
  pmcid?: string;
  meshTerms: unknown[];
}

/** A single gene record parsed from efetch XML. */
export interface GeneRecord {
  geneId: unknown;
  symbol: unknown;
  description: unknown;
  chromosome: unknown;
  synonyms: unknown[];
}

/** Shape of the JSON payload returned by NCBI esearch.fcgi. */
interface ESearchResponse {
  esearchresult: {
    idlist?: string[];
    count?: string;
    retmax?: string;
    retstart?: string;
    querytranslation?: string;
  };
}

export class NCBIClient extends BaseApiClient {
  constructor() {
    super({
      baseUrl: "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/",
      rateLimiter: {
        points: 3,
        duration: 1,
      },
      userAgent: "BioMCP/1.0.0 (biomedical-research@example.com)",
    });
  }
  async searchPubMed(term: string, options: PubMedSearchOptions = {}): Promise<PubMedSearchResult> {
    const params: Record<string, string> = {
      db: "pubmed",
      term: term,
      retmode: "json",
      retmax: String(options.retmax || 20),
      retstart: String(options.retstart || 0),
      ...(options.sort && { sort: options.sort }),
      ...(options.datetype && { datetype: options.datetype }),
      ...(options.mindate && { mindate: options.mindate }),
      ...(options.maxdate && { maxdate: options.maxdate }),
    };
    const response = await this.makeRequest<ESearchResponse>("esearch.fcgi", { params, responseType: "json" });
    if (!response.success || !response.data) {
      throw new Error(response.error || "Failed to search PubMed");
    }
    const result = response.data.esearchresult;
    return {
      idList: result.idlist || [],
      count: parseInt(result.count || "0"),
      retMax: parseInt(result.retmax || "0"),
      retStart: parseInt(result.retstart || "0"),
      queryTranslation: result.querytranslation,
    };
  }
  async fetchPubMedDetails(pmids: string[]): Promise<PubMedArticle[]> {
    if (pmids.length === 0) return [];
    const params: Record<string, string> = {
      db: "pubmed",
      id: pmids.join(","),
      retmode: "xml",
      rettype: "abstract",
    };
    const response = await this.makeRequest<string>("efetch.fcgi", { params, responseType: "text" });
    if (!response.success || !response.data) {
      throw new Error(response.error || "Failed to fetch PubMed details");
    }
    return this.parsePubMedXML(response.data);
  }
  async searchGene(term: string, organism: string = "human"): Promise<GeneSearchResult> {
    const searchTerm =
      organism === "human"
        ? `${term}[Gene Name] AND "Homo sapiens"[Organism]`
        : `${term}[Gene Name] AND "${organism}"[Organism]`;
    const params: Record<string, string> = {
      db: "gene",
      term: searchTerm,
      retmode: "json",
      retmax: "20",
    };
    const response = await this.makeRequest<ESearchResponse>("esearch.fcgi", { params, responseType: "json" });
    if (!response.success || !response.data) {
      throw new Error(response.error || "Failed to search genes");
    }
    const result = response.data.esearchresult;
    return {
      idList: result.idlist || [],
      count: parseInt(result.count || "0"),
    };
  }
  async fetchGeneDetails(geneIds: string[]): Promise<GeneRecord[]> {
    if (geneIds.length === 0) return [];
    const params: Record<string, string> = {
      db: "gene",
      id: geneIds.join(","),
      retmode: "xml",
    };
    const response = await this.makeRequest<string>("efetch.fcgi", { params, responseType: "text" });
    if (!response.success || !response.data) {
      throw new Error(response.error || "Failed to fetch gene details");
    }
    return this.parseGeneXML(response.data);
  }
  private async parsePubMedXML(xmlData: string): Promise<PubMedArticle[]> {
    try {
      const result = (await parseXML(xmlData)) as any;
      const articles = result.PubmedArticleSet?.PubmedArticle || [];
      return articles.map((article: any) => {
        const medlineCitation = article.MedlineCitation?.[0];
        const pmid = medlineCitation?.PMID?.[0]?._ || medlineCitation?.PMID?.[0];
        const articleData = medlineCitation?.Article?.[0];
        const title = articleData?.ArticleTitle?.[0] || "";
        const abstract =
          articleData?.Abstract?.[0]?.AbstractText?.[0]?._ || articleData?.Abstract?.[0]?.AbstractText?.[0] || "";
        const authors =
          articleData?.AuthorList?.[0]?.Author?.map((author: any) => {
            const lastName = author.LastName?.[0] || "";
            const foreName = author.ForeName?.[0] || author.FirstName?.[0] || "";
            return `${foreName} ${lastName}`.trim();
          }) || [];
        const journal = articleData?.Journal?.[0]?.Title?.[0] || "";
        const pubDate = articleData?.Journal?.[0]?.JournalIssue?.[0]?.PubDate?.[0];
        const year = pubDate?.Year?.[0] || "";
        const month = pubDate?.Month?.[0] || "";
        const day = pubDate?.Day?.[0] || "";
        const publicationDate = [year, month, day].filter(Boolean).join("-");
        const articleIds = article.PubmedData?.[0]?.ArticleIdList?.[0]?.ArticleId || [];
        let doi = "";
        let pmcid = "";
        articleIds.forEach((id: any) => {
          if (id.$.IdType === "doi") {
            doi = id._;
          } else if (id.$.IdType === "pmc") {
            pmcid = id._;
          }
        });
        const meshTerms =
          medlineCitation?.MeshHeadingList?.[0]?.MeshHeading?.map(
            (mesh: any) => mesh.DescriptorName?.[0]?._ || mesh.DescriptorName?.[0]
          ) || [];
        return {
          pmid,
          title,
          abstract,
          authors,
          journal,
          publicationDate,
          doi: doi || undefined,
          pmcid: pmcid || undefined,
          meshTerms,
        };
      });
    } catch (error) {
      throw new Error(`Failed to parse PubMed XML: ${error}`);
    }
  }
  private async parseGeneXML(xmlData: string): Promise<GeneRecord[]> {
    try {
      const result = (await parseXML(xmlData)) as any;
      const genes = result.Entrezgene_Set?.Entrezgene || [];
      return genes.map((gene: any) => {
        const geneRef = gene["Entrezgene_gene"]?.[0]?.["Gene-ref"]?.[0];
        const geneId = gene["Entrezgene_track-info"]?.[0]?.["Gene-track"]?.[0]?.["Gene-track_geneid"]?.[0];
        const symbol = geneRef?.["Gene-ref_locus"]?.[0] || "";
        const description = geneRef?.["Gene-ref_desc"]?.[0] || "";
        const synonyms = geneRef?.["Gene-ref_syn"]?.[0]?.["Gene-ref_syn_E"]?.map((syn: any) => syn) || [];
        const location = gene["Entrezgene_location"]?.[0];
        const chromosome = location?.["Maps"]?.[0]?.["Maps_display-str"]?.[0] || "";
        return {
          geneId,
          symbol,
          description,
          chromosome,
          synonyms,
        };
      });
    } catch (error) {
      throw new Error(`Failed to parse Gene XML: ${error}`);
    }
  }
}
