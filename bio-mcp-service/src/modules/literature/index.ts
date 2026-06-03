import { NCBIClient, PubMedArticle } from "../../utils/api-clients/ncbi-client.js";
import { MemoryCache } from "../../utils/cache/memory-cache.js";
import { PubMedSearchSchema } from "../../utils/validation/schemas.js";

export interface ToolTextContent {
  type: "text";
  text: string;
}

export interface ToolResult {
  content: ToolTextContent[];
  isError?: boolean;
}

export interface CitationNetwork {
  main_article: PubMedArticle;
  citing_articles: PubMedArticle[];
  cited_articles: PubMedArticle[];
  network_depth: number;
  pmid: string;
}

export interface CitationNetworkArgs {
  pmid?: unknown;
  depth?: number;
}

export interface ArticleAnalysis {
  article: PubMedArticle;
  analysis: {
    word_count: number;
    key_terms: unknown[];
    research_type: string;
    methodology_mentioned: boolean;
    statistical_analysis: boolean;
  };
}

export class LiteratureModule {
  ncbiClient: NCBIClient;
  cache: MemoryCache;
  constructor(cache: MemoryCache) {
    this.ncbiClient = new NCBIClient();
    this.cache = cache;
  }
  async searchPubMed(args: unknown): Promise<ToolResult> {
    try {
      const validatedArgs = PubMedSearchSchema.parse(args);
      const cacheKey = this.cache.generateKey(
        "pubmed_search",
        validatedArgs.query,
        validatedArgs.limit,
        validatedArgs.sort,
        JSON.stringify(validatedArgs.filters || {})
      );
      const cachedResult = this.cache.get<PubMedArticle[]>(cacheKey);
      if (cachedResult) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  results: cachedResult,
                  cached: true,
                  query: validatedArgs.query,
                  total_results: cachedResult.length,
                },
                null,
                2
              ),
            },
          ],
        };
      }
      let searchTerm = validatedArgs.query;
      if (validatedArgs.filters) {
        const { filters } = validatedArgs;
        if (filters.publication_date_start && filters.publication_date_end) {
          const startDate = filters.publication_date_start.replace(/-/g, "/");
          const endDate = filters.publication_date_end.replace(/-/g, "/");
          searchTerm += ` AND ("${startDate}"[Date - Publication] : "${endDate}"[Date - Publication])`;
        }
        if (filters.journal) {
          searchTerm += ` AND "${filters.journal}"[Journal]`;
        }
        if (filters.author) {
          searchTerm += ` AND "${filters.author}"[Author]`;
        }
        if (filters.article_type && filters.article_type.length > 0) {
          const types = filters.article_type.map((type) => `"${type}"[Publication Type]`).join(" OR ");
          searchTerm += ` AND (${types})`;
        }
      }
      const searchResult = await this.ncbiClient.searchPubMed(searchTerm, {
        retmax: validatedArgs.limit,
        sort: this.mapSortOrder(validatedArgs.sort),
      });
      if (searchResult.idList.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  results: [],
                  query: validatedArgs.query,
                  total_results: 0,
                  message: "No articles found for the given query",
                },
                null,
                2
              ),
            },
          ],
        };
      }
      const articles = await this.ncbiClient.fetchPubMedDetails(searchResult.idList);
      this.cache.set(cacheKey, articles, 300000);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                results: articles,
                query: validatedArgs.query,
                total_results: searchResult.count,
                returned_results: articles.length,
                search_details: {
                  query_translation: searchResult.queryTranslation,
                  search_term_used: searchTerm,
                },
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
            text: `Error searching PubMed: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  async getCitationNetwork(args: CitationNetworkArgs): Promise<ToolResult> {
    try {
      const { pmid, depth = 1 } = args;
      if (!pmid || typeof pmid !== "string") {
        throw new Error("Valid PMID is required");
      }
      if (depth < 1 || depth > 3) {
        throw new Error("Depth must be between 1 and 3");
      }
      const cacheKey = this.cache.generateKey("citation_network", pmid, depth);
      const cachedResult = this.cache.get<CitationNetwork>(cacheKey);
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
      const mainArticle = await this.ncbiClient.fetchPubMedDetails([pmid]);
      if (mainArticle.length === 0) {
        throw new Error(`Article with PMID ${pmid} not found`);
      }
      const citationNetwork: CitationNetwork = {
        main_article: mainArticle[0],
        citing_articles: [],
        cited_articles: [],
        network_depth: depth,
        pmid,
      };
      if (depth >= 1) {
        try {
          const citingQuery = `"${pmid}"[PMID] AND haslinks[text]`;
          const citingResult = await this.ncbiClient.searchPubMed(citingQuery, {
            retmax: 10,
          });
          if (citingResult.idList.length > 0) {
            citationNetwork.citing_articles = await this.ncbiClient.fetchPubMedDetails(citingResult.idList.slice(0, 5));
          }
        } catch (error) {
          console.error("Error finding citing articles:", error);
        }
      }
      this.cache.set(cacheKey, citationNetwork, 600000);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(citationNetwork, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error building citation network: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }
  mapSortOrder(sort: string): string {
    switch (sort) {
      case "publication_date":
        return "pub+date";
      case "first_author":
        return "first+author";
      case "relevance":
      default:
        return "relevance";
    }
  }
  async analyzeArticle(pmid: string): Promise<ArticleAnalysis> {
    const articles = await this.ncbiClient.fetchPubMedDetails([pmid]);
    if (articles.length === 0) {
      throw new Error(`Article with PMID ${pmid} not found`);
    }
    const article = articles[0];
    const text = `${article.title} ${article.abstract}`.toLowerCase();
    const wordCount = text.split(/\s+/).length;
    const keyTerms = article.meshTerms || [];
    let researchType = "unknown";
    if (text.includes("randomized") || text.includes("clinical trial")) {
      researchType = "clinical_trial";
    } else if (text.includes("systematic review") || text.includes("meta-analysis")) {
      researchType = "systematic_review";
    } else if (text.includes("case study") || text.includes("case report")) {
      researchType = "case_study";
    } else if (text.includes("cohort") || text.includes("longitudinal")) {
      researchType = "observational";
    } else if (text.includes("in vitro") || text.includes("cell culture")) {
      researchType = "experimental";
    }
    const methodologyKeywords = ["method", "methodology", "protocol", "procedure", "technique"];
    const methodologyMentioned = methodologyKeywords.some((keyword) => text.includes(keyword));
    const statisticalKeywords = ["p-value", "confidence interval", "statistical", "regression", "anova", "t-test"];
    const statisticalAnalysis = statisticalKeywords.some((keyword) => text.includes(keyword));
    return {
      article,
      analysis: {
        word_count: wordCount,
        key_terms: keyTerms.slice(0, 10),
        research_type: researchType,
        methodology_mentioned: methodologyMentioned,
        statistical_analysis: statisticalAnalysis,
      },
    };
  }
}
