/** CTS files emit CommonJS under NodeNext regardless of their import syntax. */
export const typescriptSourceModuleKind = (
  sourcePath: string,
): "require" | null => (/\.cts$/iu.test(sourcePath) ? "require" : null);
