package container

import (
	"context"
	"fmt"
	"io"
	"net/http/httputil"
	"os"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/opts"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/signal"
	"github.com/docker/docker/pkg/term"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type runOptions struct {
	createOptions
	detach     bool
	sigProxy   bool
	detachKeys string
}

// NewRunCommand create a new `docker run` command
func NewRunCommand(dockerCli command.Cli) *cobra.Command {
	var opts runOptions
	var copts *containerOptions

	cmd := &cobra.Command{
		Use:   "run [OPTIONS] IMAGE [COMMAND] [ARG...]",
		Short: "Run a command in a new container",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// 获取镜像
			copts.Image = args[0]
			if len(args) > 1 {
				copts.Args = args[1:]
			}
			return runRun(dockerCli, cmd.Flags(), &opts, copts)
		},
	}

	flags := cmd.Flags()
	flags.SetInterspersed(false)

	// These are flags not stored in Config/HostConfig
	flags.BoolVarP(&opts.detach, "detach", "d", false, "Run container in background and print container ID")
	flags.BoolVar(&opts.sigProxy, "sig-proxy", true, "Proxy received signals to the process")
	flags.StringVar(&opts.name, "name", "", "Assign a name to the container")
	flags.StringVar(&opts.detachKeys, "detach-keys", "", "Override the key sequence for detaching a container")

	// Add an explicit help that doesn't have a `-h` to prevent the conflict
	// with hostname
	flags.Bool("help", false, "Print usage")

	command.AddPlatformFlag(flags, &opts.platform)
	command.AddTrustVerificationFlags(flags, &opts.untrusted, dockerCli.ContentTrustEnabled())
	// 添加 flags
	copts = addFlags(flags)
	return cmd
}

func warnOnOomKillDisable(hostConfig container.HostConfig, stderr io.Writer) {
	if hostConfig.OomKillDisable != nil && *hostConfig.OomKillDisable && hostConfig.Memory == 0 {
		fmt.Fprintln(stderr, "WARNING: Disabling the OOM killer on containers without setting a '-m/--memory' limit may be dangerous.")
	}
}

// check the DNS settings passed via --dns against localhost regexp to warn if
// they are trying to set a DNS to a localhost address
func warnOnLocalhostDNS(hostConfig container.HostConfig, stderr io.Writer) {
	for _, dnsIP := range hostConfig.DNS {
		if isLocalhost(dnsIP) {
			fmt.Fprintf(stderr, "WARNING: Localhost DNS setting (--dns=%s) may fail in containers.\n", dnsIP)
			return
		}
	}
}

// IPLocalhost is a regex pattern for IPv4 or IPv6 loopback range.
const ipLocalhost = `((127\.([0-9]{1,3}\.){2}[0-9]{1,3})|(::1)$)`

var localhostIPRegexp = regexp.MustCompile(ipLocalhost)

// IsLocalhost returns true if ip matches the localhost IP regular expression.
// Used for determining if nameserver settings are being passed which are
// localhost addresses
func isLocalhost(ip string) bool {
	return localhostIPRegexp.MatchString(ip)
}

func runRun(dockerCli command.Cli, flags *pflag.FlagSet, ropts *runOptions, copts *containerOptions) error {

	// 获取代理配置
	proxyConfig := dockerCli.ConfigFile().ParseProxyConfig(dockerCli.Client().DaemonHost(), copts.env.GetAll())
	newEnv := []string{}
	for k, v := range proxyConfig {
		if v == nil {
			newEnv = append(newEnv, k)
		} else {
			newEnv = append(newEnv, fmt.Sprintf("%s=%s", k, *v))
		}
	}
	copts.env = *opts.NewListOptsRef(&newEnv, nil)
	// 解析flag -> 容器配置
	containerConfig, err := parse(flags, copts)
	// just in case the parse does not exit
	if err != nil {
		reportError(dockerCli.Err(), "run", err.Error(), true)
		return cli.StatusError{StatusCode: 125}
	}
	return runContainer(dockerCli, ropts, copts, containerConfig)
}

// nolint: gocyclo
func runContainer(dockerCli command.Cli, opts *runOptions, copts *containerOptions, containerConfig *containerConfig) error {
	// 获取容器配置
	config := containerConfig.Config
	// 获取主机配置
	hostConfig := containerConfig.HostConfig
	stdout, stderr := dockerCli.Out(), dockerCli.Err()
	// 获取docker客户端
	client := dockerCli.Client()

	// 如果设置了 --oom-kill-disable 会有Warning提示
	// docker container run -it --oom-kill-disable --rm alpine sh
	warnOnOomKillDisable(*hostConfig, stderr)
	// 如果设置了 --dns 127.x.x.x 会有Warning提示
	// docker container run -it --dns 127.0.0.1 --rm alpine sh
	warnOnLocalhostDNS(*hostConfig, stderr)

	config.ArgsEscaped = false

	// 检测是否为 -d 守护模式
	if !opts.detach {
		// 非守护模式 检测tty
		if err := dockerCli.In().CheckTty(config.AttachStdin, config.Tty); err != nil {
			return err
		}
	} else {
		// 同时设置了 -a 与 -d 会报错
		// docker run -d -a STDOUT alpine sh
		if copts.attach.Len() != 0 {
			return errors.New("Conflicting options: -a and -d")
		}

		config.AttachStdin = false
		config.AttachStdout = false
		config.AttachStderr = false
		config.StdinOnce = false
	}

	// Disable sigProxy when in TTY mode
	// 如果设置了 TTY 会禁用 --sig-proxy
	if config.Tty {
		opts.sigProxy = false
	}

	// Telling the Windows daemon the initial size of the tty during start makes
	// a far better user experience rather than relying on subsequent resizes
	// to cause things to catch up.
	// 如果运行时是windows 会初始化TTY
	if runtime.GOOS == "windows" {
		hostConfig.ConsoleSize[0], hostConfig.ConsoleSize[1] = dockerCli.Out().GetTtySize()
	}

	// 设置可取消的Context
	ctx, cancelFun := context.WithCancel(context.Background())
	defer cancelFun()

	// 创建容器(不运行)
	createResponse, err := createContainer(ctx, dockerCli, containerConfig, &opts.createOptions)
	if err != nil {
		reportError(stderr, "run", err.Error(), true)
		return runStartContainerErr(err)
	}
	// --sig-proxy 默认开启 除非设置了 -t
	if opts.sigProxy {
		// 转发所有的信号给容器
		sigc := ForwardAllSignals(ctx, dockerCli, createResponse.ID)
		defer signal.StopCatch(sigc)
	}

	var (
		waitDisplayID chan struct{}
		errCh         chan error
	)
	// 如果 stdout stderr 分离会打印出容器 ID
	if !config.AttachStdout && !config.AttachStderr {
		// Make this asynchronous to allow the client to write to stdin before having to read the ID
		waitDisplayID = make(chan struct{})
		go func() {
			defer close(waitDisplayID)
			fmt.Fprintln(stdout, createResponse.ID)
		}()
	}
	attach := config.AttachStdin || config.AttachStdout || config.AttachStderr
	if attach {
		// 修改默认的分离快捷键
		// https://stackoverflow.com/a/50019551
		if opts.detachKeys != "" {
			dockerCli.ConfigFile().DetachKeys = opts.detachKeys
		}
		// 如果有 attach stdin/stdout/stderr 会attach到容器
		close, err := attachContainer(ctx, dockerCli, &errCh, config, createResponse.ID)

		if err != nil {
			return err
		}
		defer close()
	}

	// 等待容器退出或者被移除
	statusChan := waitExitOrRemoved(ctx, dockerCli, createResponse.ID, copts.autoRemove)

	//start the container
	// 启动容器
	if err := client.ContainerStart(ctx, createResponse.ID, types.ContainerStartOptions{}); err != nil {
		// If we have hijackedIOStreamer, we should notify
		// hijackedIOStreamer we are going to exit and wait
		// to avoid the terminal are not restored.
		if attach {
			cancelFun()
			<-errCh
		}

		reportError(stderr, "run", err.Error(), false)
		if copts.autoRemove {
			// wait container to be removed
			<-statusChan
		}
		return runStartContainerErr(err)
	}

	// 监视TTY
	if (config.AttachStdin || config.AttachStdout || config.AttachStderr) && config.Tty && dockerCli.Out().IsTerminal() {
		if err := MonitorTtySize(ctx, dockerCli, createResponse.ID, false); err != nil {
			fmt.Fprintln(stderr, "Error monitoring TTY size:", err)
		}
	}

	if errCh != nil {
		if err := <-errCh; err != nil {
			if _, ok := err.(term.EscapeError); ok {
				// The user entered the detach escape sequence.
				return nil
			}

			logrus.Debugf("Error hijack: %s", err)
			return err
		}
	}

	// Detached mode: wait for the id to be displayed and return.
	// -d Detached模式会等待显示容器ID
	// docker container run -d --rm alpine sh
	if !config.AttachStdout && !config.AttachStderr {
		// Detached mode
		<-waitDisplayID
		return nil
	}

	status := <-statusChan
	if status != 0 {
		return cli.StatusError{StatusCode: status}
	}
	return nil
}

func attachContainer(
	ctx context.Context,
	dockerCli command.Cli,
	errCh *chan error,
	config *container.Config,
	containerID string,
) (func(), error) {
	stdout, stderr := dockerCli.Out(), dockerCli.Err()
	var (
		out, cerr io.Writer
		in        io.ReadCloser
	)
	if config.AttachStdin {
		in = dockerCli.In()
	}
	if config.AttachStdout {
		out = stdout
	}
	if config.AttachStderr {
		if config.Tty {
			cerr = stdout
		} else {
			cerr = stderr
		}
	}

	options := types.ContainerAttachOptions{
		Stream:     true,
		Stdin:      config.AttachStdin,
		Stdout:     config.AttachStdout,
		Stderr:     config.AttachStderr,
		DetachKeys: dockerCli.ConfigFile().DetachKeys,
	}

	resp, errAttach := dockerCli.Client().ContainerAttach(ctx, containerID, options)
	if errAttach != nil && errAttach != httputil.ErrPersistEOF {
		// ContainerAttach returns an ErrPersistEOF (connection closed)
		// means server met an error and put it in Hijacked connection
		// keep the error and read detailed error message from hijacked connection later
		return nil, errAttach
	}

	ch := make(chan error, 1)
	*errCh = ch

	go func() {
		ch <- func() error {
			streamer := hijackedIOStreamer{
				streams:      dockerCli,
				inputStream:  in,
				outputStream: out,
				errorStream:  cerr,
				resp:         resp,
				tty:          config.Tty,
				detachKeys:   options.DetachKeys,
			}

			if errHijack := streamer.stream(ctx); errHijack != nil {
				return errHijack
			}
			return errAttach
		}()
	}()
	return resp.Close, nil
}

// reportError is a utility method that prints a user-friendly message
// containing the error that occurred during parsing and a suggestion to get help
func reportError(stderr io.Writer, name string, str string, withHelp bool) {
	str = strings.TrimSuffix(str, ".") + "."
	if withHelp {
		str += "\nSee '" + os.Args[0] + " " + name + " --help'."
	}
	fmt.Fprintf(stderr, "%s: %s\n", os.Args[0], str)
}

// if container start fails with 'not found'/'no such' error, return 127
// if container start fails with 'permission denied' error, return 126
// return 125 for generic docker daemon failures
func runStartContainerErr(err error) error {
	trimmedErr := strings.TrimPrefix(err.Error(), "Error response from daemon: ")
	statusError := cli.StatusError{StatusCode: 125}
	if strings.Contains(trimmedErr, "executable file not found") ||
		strings.Contains(trimmedErr, "no such file or directory") ||
		strings.Contains(trimmedErr, "system cannot find the file specified") {
		statusError = cli.StatusError{StatusCode: 127}
	} else if strings.Contains(trimmedErr, syscall.EACCES.Error()) {
		statusError = cli.StatusError{StatusCode: 126}
	}

	return statusError
}
