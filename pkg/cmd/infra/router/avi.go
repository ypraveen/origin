package router

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"

	"github.com/openshift/origin/pkg/cmd/util"
	"github.com/openshift/origin/pkg/cmd/util/clientcmd"
	"github.com/openshift/origin/pkg/router/controller"
	"github.com/openshift/origin/pkg/version"
	aviplugin "github.com/openshift/origin/plugins/router/avi"
)

const (
	aviLong = `
Start an Avi route synchronizer

This command launches a process that will synchronize Avi to the route configuration of your master.

You may restrict the set of routes exposed to a single project (with --namespace), projects your client has
access to with a set of labels (--project-labels), namespaces matching a label (--namespace-labels), or all
namespaces (no argument). You can limit the routes to those matching a --labels or --fields selector. Note
that you must have a cluster-wide administrative role to view all namespaces.`
)

// AviRouterOptions represent the complete structure needed to start an Avi router
// sync process.
type AviRouterOptions struct {
	Config *clientcmd.Config

	AviRouter
	RouterSelection
}

// AviRouter is the config necessary to start an Avi router plugin.
type AviRouter struct {
	// Host specifies the hostname or IP address of the Avi Controller.
	Host string

	// Username specifies the username with which the plugin should authenticate
	// with the Avi Controller.
	Username string

	// Password specifies the password with which the plugin should authenticate
	// with the Avi Controller.
	Password string

	// virtual service to use for managing routes
	VSname string

	// cloud on avi controller
	Cloudname string

	// Insecure specifies whether the Avi plugin should perform strict certificate
	// validation for connections to the Avi Controller
	Insecure bool
}

// Bind binds AviRouter arguments to flags
func (o *AviRouter) Bind(flag *pflag.FlagSet) {
	flag.StringVar(&o.Host, "avi-host", util.Env("ROUTER_EXTERNAL_HOST_HOSTNAME", ""), "The Avi Controller host name or ip address")
	flag.StringVar(&o.Username, "avi-username", util.Env("ROUTER_EXTERNAL_HOST_USERNAME", ""), "The username for Avi Controller")
	flag.StringVar(&o.Password, "avi-password", util.Env("ROUTER_EXTERNAL_HOST_PASSWORD", ""), "The password for Avi Controller")
	flag.StringVar(&o.VSname, "avi-vsname", util.Env("ROUTER_EXTERNAL_HOST_HTTP_VSERVER", "openshift-router"), "The virtual service for managing routes")
	flag.StringVar(&o.Cloudname, "avi-cloudname", util.Env("ROUTER_EXTERNAL_PARTITION_PATH", "Default-Cloud"), "The Cloud to use on Avi Controller")
	flag.BoolVar(&o.Insecure, "avi-insecure", util.Env("ROUTER_EXTERNAL_HOST_INSECURE", "") == "true", "Skip strict certificate verification")
}

// Validate verifies the required Avi flags are present
func (o *AviRouter) Validate() error {
	if o.Host == "" {
		return errors.New("Avi Controller host must be specified")
	}

	if o.Username == "" {
		return errors.New("Avi Controller username must be specified")
	}

	if o.Password == "" {
		return errors.New("Avi Controller password must be specified")
	}

	return nil
}

// NewCommandAviRouter provides CLI handler for the Avi router sync plugin.
func NewCommandAviRouter(name string) *cobra.Command {
	options := &AviRouterOptions{
		Config: clientcmd.NewConfig(),
	}
	options.Config.FromFile = true

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("%s%s", name, clientcmd.ConfigSyntax),
		Short: "Start an Avi route synchronizer",
		Long:  aviLong,
		Run: func(c *cobra.Command, args []string) {
			options.RouterSelection.Namespace = cmdutil.GetFlagString(c, "namespace")
			cmdutil.CheckErr(options.Complete())
			cmdutil.CheckErr(options.Validate())
			cmdutil.CheckErr(options.Run())
		},
	}

	cmd.AddCommand(version.NewVersionCommand(name, false))

	flag := cmd.Flags()
	options.Config.Bind(flag)
	options.AviRouter.Bind(flag)
	options.RouterSelection.Bind(flag)

	return cmd
}

func (o *AviRouterOptions) Complete() error {
	return o.RouterSelection.Complete()
}

func (o *AviRouterOptions) Validate() error {
	return o.AviRouter.Validate()
}

// Run launches an Avi route sync process using the provided options. It never exits.
func (o *AviRouterOptions) Run() error {
	cfg := aviplugin.AviPluginConfig{
		Host:          o.Host,
		Username:      o.Username,
		Password:      o.Password,
		VSname:        o.VSname,
		Cloudname:     o.Cloudname,
		Insecure:      o.Insecure,
	}
	aviPlugin, err := aviplugin.NewAviPlugin(cfg)
	if err != nil {
		return err
	}

	plugin := controller.NewUniqueHost(aviPlugin, o.RouteSelectionFunc())

	oc, kc, err := o.Config.Clients()
	if err != nil {
		return err
	}

	factory := o.RouterSelection.NewFactory(oc, kc)
	controller := factory.Create(plugin)
	controller.Run()

	select {}
}
