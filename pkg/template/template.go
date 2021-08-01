package template

type Template struct {
	Callbacks []Callback `yaml:"callbacks"`
}

type Callback struct {
	Name string `yaml:"name"`
	DSL  string `yaml:"dsl"`
	Code string `yaml:"code"`
}
