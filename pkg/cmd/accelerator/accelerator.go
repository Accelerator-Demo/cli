package accelerator

import (
	deployCmd "github.com/cli/cli/pkg/cmd/accelerator/bootstrap"
	"github.com/cli/cli/pkg/cmdutil"
	"github.com/spf13/cobra"
)

func NewCmdAccelerator(f *cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accelerator <command>",
		Short: "Bootstrap your application",
		Long:  `Bootstrap your application`,
	}

	cmdutil.DisableAuthCheck(cmd)

	cmd.AddCommand(deployCmd.NewCmdBootstrap(f, nil))

	return cmd
}
