package derivation

import (
	"fmt"
	"io"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/nix-community/go-nix/pkg/nixpath"
)

type Derivation struct {
	_                string            `parser:"@DerivationPrefix"`
	Outputs          []Output          `json:"outputs" parser:"'[' ((@@ ','?)* @@? )']'','"`
	InputDerivations []InputDerivation `json:"inputDrvs" parser:"'[' ((@@ ','?)* @@? )?']'','"`
	InputSources     []string          `json:"inputSrcs" parser:"'[' ((@NixPath ','?)* @NixPath? )?']'','"`
	Platform         string            `json:"system" parser:"@String ','"`
	Builder          string            `json:"builder" parser:"@String ','"`
	Arguments        []string          `json:"args" parser:"'[' ((@String ','?)* (@NixPath|@String)? )?']'','"`
	EnvVars          []Env             `json:"env" parser:"'[' ((@@ ','?)* (@@)? )']'')'"`
}

type Output struct {
	Content       string `json:"name" parser:"'(' @String ','"`
	Path          string `json:"path" parser:"@NixPath ','"`
	HashAlgorithm string `json:"hashAlgo" parser:"@String ','"`
	Hash          string `json:"hash" parser:"@String ')'"`
}

type InputDerivation struct {
	Path string   `json:"path" parser:"'(' @NixPath ','"`
	Name []string `json:"name" parser:"'[' ((@String ','?)* @String? )']' ')'"`
}

type Env struct {
	Key   string `parser:"'(' @String ','"`
	Value string `parser:"(@String|@NixPath)? ')'"`
}

func ReadDerivation(reader io.Reader) (*Derivation, error) {
	drv := Derivation{}
	iniLexer := lexer.MustSimple([]lexer.Rule{
		{Name: `NixPath`, Pattern: fmt.Sprintf(`"/nix/store/%v"`, nixpath.NameRe.String())},
		{Name: `DerivationPrefix`, Pattern: `^Derive\(`},
		{Name: `String`, Pattern: `"(?:\\.|[^"])*"`},
		{Name: `Delim`, Pattern: `[,()\[\]]`},
		{Name: "Whitespace", Pattern: `[ \t\n\r]+`},
	})

	parser := participle.MustBuild(&Derivation{},
		participle.Lexer(iniLexer),
		participle.Elide("Whitespace", "DerivationPrefix"),
		participle.Unquote("NixPath", "String"),
	)

	err := parser.Parse("", reader, &drv)

	return &drv, err
}
