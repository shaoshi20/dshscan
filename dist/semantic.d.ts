import type { SemanticResult } from "./types.js";
export interface SemanticInput {
    displayName: string;
    readme: string;
    codeExcerpts: string[];
    model?: string;
    baseUrl?: string;
    apiKey?: string;
}
export declare function runSemantic(input: SemanticInput): Promise<SemanticResult>;
