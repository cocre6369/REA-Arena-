import * as t from "@babel/types";

/** A value import-equals declaration has require semantics and an immutable alias. */
export const typescriptRequireImport = (
  node: t.Node,
): { readonly name: t.Identifier; readonly specifier: string } | null => {
  if (
    !t.isTSImportEqualsDeclaration(node) ||
    node.importKind === "type" ||
    !t.isTSExternalModuleReference(node.moduleReference) ||
    !t.isStringLiteral(node.moduleReference.expression)
  )
    return null;
  return {
    name: node.id,
    specifier: node.moduleReference.expression.value,
  };
};
