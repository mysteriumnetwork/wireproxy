package wgstack

import (
	"context"
	"fmt"
	"net"

	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdev "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
	wgstack "golang.zx2c4.com/wireguard/tun/netstack"
)

const DefaultMTU = wgdev.DefaultMTU

type Logger func (string, ...interface{})

type WGStack struct {
	dev *wgdev.Device
	tun wgtun.Device
	tnet *wgstack.Net
}

type WGStackConfig struct {
	LocalAddresses []net.IP
	DNSServers []net.IP
	InitCommands string
	MTU int
	Logger Logger
	ErrorLogger Logger
}

func NewWGStack(conf *WGStackConfig) (*WGStack, error) {
	mtu := conf.MTU
	if mtu < 1 {
		mtu = wgdev.DefaultMTU
	}
	tun, tnet, err := wgstack.CreateNetTUN(
		conf.LocalAddresses,
		conf.DNSServers,
		mtu)
	if err != nil {
		return nil, fmt.Errorf("unable to create virtual netdev: %w", err)
	}

	logger := conf.Logger
	if logger == nil {
		logger = func (_ string, _ ...interface{}) {}
	}

	errorLogger := conf.ErrorLogger
	if errorLogger == nil {
		errorLogger = func (_ string, _ ...interface{}) {}
	}

	dev := wgdev.NewDevice(tun, wgconn.NewDefaultBind(), &wgdev.Logger{logger, errorLogger})
	err = dev.IpcSet(conf.InitCommands)
	if err != nil {
		return nil, fmt.Errorf("config setting failed: %w", err)
	}

	dev.Up()

	wgst := WGStack{
		dev: dev,
		tun: tun,
		tnet: tnet,
	}
	return &wgst, nil

}

func (wgst *WGStack) Close() error {
	if err := wgst.dev.Down(); err != nil {
		return err
	}

	return wgst.tun.Close()
}

func (wgst *WGStack) DialContext(ctx context.Context, net, addr string) (net.Conn, error) {
	return wgst.tnet.DialContext(ctx, net, addr)
}

func (wgst *WGStack) IpcGet() (string, error) {
	return wgst.dev.IpcGet()
}

func (wgst *WGStack) IpcSet(uapiConf string) error {
	return wgst.dev.IpcSet(uapiConf)
}
