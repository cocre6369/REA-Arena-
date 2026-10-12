@inline(never)
func consume(_ value: String) { print(value) }
@inline(never)
func smallLiteral() { consume("SleepDisabled") }
@inline(never)
func largeLiteral() { consume("The power setting could not be changed.") }
@inline(never)
func unicodeLiterals() {
  consume("café")
  consume("Résumé of the naïve décor, written twice")
}
@inline(never)
func returnedLiteral() -> String { "Holding awake" }
smallLiteral()
largeLiteral()
unicodeLiterals()
print(returnedLiteral(), CommandLine.arguments.count)
