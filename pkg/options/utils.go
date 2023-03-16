package options

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

const Version = "1.1.1"

var banner = fmt.Sprintf(`
    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ %s
`, Version)

func ShowBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates interactsh
func GetUpdateCallback(assetName string) func() {
	return func() {
		ShowBanner()
		updateutils.GHAssetName = assetName
		updateutils.GetUpdateToolCallback("interactsh", Version)()
	}
}
