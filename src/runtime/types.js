/**
 * @typedef {{
 *   match: string,
 *   replace: any
 * }} RegexRule
 */

/**
 * @typedef {{
 *   key: string,
 *   value: any
 * }} QueryMod
 */

/**
 * @typedef {{
 *   domain?: RegexRule[],
 *   path?: RegexRule[],
 *   query?: QueryMod[]
 * }} URLMods
 */

/**
 * @typedef {{
 *   position?: string,
 *   append?: string,
 *   prepend?: string,
 *   replace?: string
 * }} Injection
 */

/**
 * @typedef {{
 *   cond?: string,
 *   hide_elem?: string,
 *   rm_elem?: boolean,
 *   rm_class?: string,
 *   rm_attrib?: string,
 *   set_attrib?: string,
 *   add_style?: string
 * }} CsCodeOp
 */

/**
 * @typedef {{
 *   domain?: string,
 *   domains?: string[],
 *   global?: boolean,
 *   bpc?: boolean,
 *   paths?: string[],
 *   pathExclusions?: string[],
 *   headers?: Record<string, string>,
 *   googleCache?: boolean,
 *   regexRules?: RegexRule[],
 *   urlMods?: URLMods,
 *   injections?: Injection[],
 *   tests?: { url?: string, test?: string }[],
 *   randomIP?: string,
 *   blockScripts?: string[],
 *   blockScriptsGeneral?: string[],
 *   excludedDomains?: string[],
 *   csCode?: CsCodeOp[],
 *   ampUnhide?: boolean,
 *   ampRedirect?: string,
 *   blockJsInline?: string,
 *   csParam?: Record<string, any>,
 *   csBlock?: boolean,
 *   csClearLocalStorage?: boolean,
 *   csAllFrames?: boolean,
 *   allowCookies?: boolean,
 *   extraHeaders?: Record<string, string>
 * }} Rule
 */

/**
 * @typedef {Rule[]} RuleSet
 */
