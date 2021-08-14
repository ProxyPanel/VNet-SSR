package service

import (
	"context"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/core"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProxyPanel/VNet-SSR/common/network"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/proxy/server"
	"github.com/ProxyPanel/VNet-SSR/utils/addrx"
	"github.com/ProxyPanel/VNet-SSR/utils/monitor"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ssrManagerInstance = NewShadowsocksrService()
)

func GetSSRManager() *SSRManager {
	return ssrManagerInstance
}

type AddUserHandle func(*model.UserInfo)
type DelUserHandle func(int)

func NewShadowsocksrService() *SSRManager {
	return &SSRManager{
		Locker:        new(sync.Mutex),
		Shadowsocksrs: make(map[int]*server.ShadowsocksRProxy),
		traffic:       make(map[int]*model.UserTraffic),
		trafficLock:   new(sync.Mutex),
		online:        make(map[int]*model.NodeOnline),
		onlineLock:    new(sync.Mutex),
		userTable:     make(map[int]*model.UserInfo),
		userTableLock: new(sync.Mutex),
		UpTime:        time.Now(),
	}
}

type SSRManager struct {
	sync.Locker
	Shadowsocksrs  map[int]*server.ShadowsocksRProxy
	traffic        map[int]*model.UserTraffic
	trafficLock    *sync.Mutex
	online         map[int]*model.NodeOnline
	onlineLock     *sync.Mutex
	userTable      map[int]*model.UserInfo
	userTableLock  *sync.Mutex
	UpTime         time.Time
	addUserHandles []AddUserHandle
	delUserHanelds []DelUserHandle
	context.Context
	cancel context.CancelFunc
}

func (s *SSRManager) uidToPortLocked(uid int) int {
	if user := s.userTable[uid]; user != nil {
		return user.Port
	}
	return 0
}

func (s *SSRManager) UIDToPort(uid int) int {
	s.userTableLock.Lock()
	result := s.uidToPortLocked(uid)
	s.userTableLock.Unlock()
	return result
}

func (s *SSRManager) portToUidLocked(port int) int {
	for _, value := range s.userTable {
		if value.Port == port {
			return value.Uid
		}
	}
	return 0
}

func (s *SSRManager) PortToUid(port int) int {
	s.userTableLock.Lock()
	result := s.portToUidLocked(port)
	s.userTableLock.Unlock()
	return result
}

func (s *SSRManager) Upload(port int, n int64) {
	s.trafficLock.Lock()
	uid := s.PortToUid(port)
	if s.traffic[uid] != nil {
		s.traffic[uid].Upload += n
	} else {
		traffic := new(model.UserTraffic)
		traffic.Upload += n
		traffic.Uid = uid
		s.traffic[uid] = traffic
	}
	s.trafficLock.Unlock()
}

func (s *SSRManager) Download(port int, n int64) {
	s.trafficLock.Lock()
	uid := s.PortToUid(port)
	if s.traffic[uid] != nil {
		s.traffic[uid].Download += n
	} else {
		traffic := new(model.UserTraffic)
		traffic.Download += n
		traffic.Uid = uid
		s.traffic[uid] = traffic
	}
	s.trafficLock.Unlock()
}

func (s *SSRManager) ReportTraffic() []*model.UserTraffic {
	s.trafficLock.Lock()
	reportData := s.traffic
	s.traffic = make(map[int]*model.UserTraffic)
	convertReportData := make([]*model.UserTraffic, 0, len(reportData))
	for key, value := range reportData {
		if value.Download+value.Upload < 50*1024 {
			continue
		}
		convertReportData = append(convertReportData, value)
		delete(s.traffic, key)
	}
	s.trafficLock.Unlock()
	return convertReportData
}

func (s *SSRManager) Online(port int, ip string) {
	s.onlineLock.Lock()
	defer s.onlineLock.Unlock()
	uid := s.PortToUid(port)
	if uid == 0 {
		log.Error("catch port %v but uid is 0", port)
		return
	}
	ip = addrx.SplitIpFromAddr(ip)
	if s.online[uid] == nil {
		nodeOnline := new(model.NodeOnline)
		nodeOnline.Uid = uid
		nodeOnline.IP = ip
		s.online[uid] = nodeOnline
	} else {
		if !strings.Contains(s.online[uid].IP, ip) {
			s.online[uid].IP = s.online[uid].IP + "," + ip
		}
	}
}

func (s *SSRManager) ReportOnline() []*model.NodeOnline {
	s.onlineLock.Lock()
	reportData := s.online
	convertReportData := make([]*model.NodeOnline, 0, len(reportData))
	for _, value := range reportData {
		convertReportData = append(convertReportData, value)
	}
	s.online = make(map[int]*model.NodeOnline)
	s.onlineLock.Unlock()
	return convertReportData
}

func (s *SSRManager) ReportNodeStatus() model.NodeStatus {
	up, down := monitor.GetNetwork()
	return model.NodeStatus{
		CPU:    fmt.Sprintf("%v%%", monitor.GetCPUUsage()),
		MEM:    fmt.Sprintf("%v%%", monitor.GetMemUsage()),
		NET:    fmt.Sprintf("%v↑-%v↓", humanize.Bytes(up), humanize.Bytes(down)),
		DISK:   fmt.Sprintf("%v%%", monitor.GetDiskUsage()),
		UPTIME: int(time.Since(s.UpTime).Seconds()),
	}
}

func (s *SSRManager) NewShadowsocksRProxy(port int, method, passwd, protocol, protocolParam, obfs, obfsParam string, single int, args *server.ShadowsocksRArgs) *server.ShadowsocksRProxy {
	host := core.GetApp().Host()
	shadowsocksRProxy := new(server.ShadowsocksRProxy)
	shadowsocksRProxy.Host = host
	shadowsocksRProxy.Port = port
	shadowsocksRProxy.Method = method
	shadowsocksRProxy.Password = passwd
	shadowsocksRProxy.Protocol = protocol
	shadowsocksRProxy.ProtocolParam = protocolParam
	shadowsocksRProxy.Obfs = obfs
	shadowsocksRProxy.ObfsParam = obfsParam
	shadowsocksRProxy.ShadowsocksRArgs = args
	shadowsocksRProxy.Listener = network.NewListener(fmt.Sprintf("%s:%v", host, port), 5*time.Second)
	shadowsocksRProxy.OnlineReport = s
	shadowsocksRProxy.TrafficReport = s
	shadowsocksRProxy.Single = single
	shadowsocksRProxy.ILimiter = GetLimitInstance()
	shadowsocksRProxy.Users = make(map[string]string)
	shadowsocksRProxy.HostFirewall = GetRuleService()
	if core.GetApp().NodeInfo().IsUDP == 1 {
		shadowsocksRProxy.UDPSwitch = "true"
	} else {
		shadowsocksRProxy.UDPSwitch = "false"
	}
	s.Shadowsocksrs[port] = shadowsocksRProxy
	return shadowsocksRProxy
}

func (s *SSRManager) AddUsers(users []*model.UserInfo) error {
	uids := make([]int, 0, len(users))
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	for _, item := range users {
		uids = append(uids, item.Uid)
		err := s.addUser(item)
		if err != nil {
			for _, uid := range uids {
				_, _ = s.delUserReturl(uid)
			}
			return err
		}
		logrus.Infof("add user,uid: %v, port: %v", item.Uid, item.Port)
	}
	return nil
}

func (s *SSRManager) DelUsers(uids []int) error {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	users := make([]*model.UserInfo, 0, len(uids))
	for _, uid := range uids {
		item, err := s.delUserReturl(uid)
		if item != nil {
			users = append(users, item)
		}
		if err != nil {
			for _, user := range users {
				_ = s.addUser(user)
			}
			return err
		}
		logrus.Infof("del uid: %v \n", uid)
	}
	return nil
}

func (s *SSRManager) GetUserByPort(port int) (user *model.UserInfo, exist bool) {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	uid := s.PortToUid(port)
	user, exist = s.userTable[uid]
	return
}

func (s *SSRManager) AddUser(user *model.UserInfo) error {
	logrus.Infof("add user,uid: %v, port: %v", user.Uid, user.Port)
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	return s.addUser(user)
}

func (s *SSRManager) addUser(user *model.UserInfo) error {
	nodeInfo := core.GetApp().NodeInfo()
	if user2 := s.userTable[user.Uid]; user2 != nil {
		return errors.New(fmt.Sprintf("user %v already exist", user2.Uid))
	}
	if nodeInfo.Single == 1 {
		for _, server := range s.Shadowsocksrs {
			server.AddUser(user.Port, user.Passwd)
		}
	} else {
		if s.Shadowsocksrs[user.Port] != nil {
			return errors.New(fmt.Sprintf("add user port %v is used by %v", user.Port, s.portToUidLocked(user.Port)))
		}
		server := s.NewShadowsocksRProxy(
			user.Port,
			nodeInfo.Method,
			user.Passwd,
			nodeInfo.Protocol,
			nodeInfo.ProtocolParam,
			nodeInfo.Obfs,
			nodeInfo.ObfsParam,
			nodeInfo.Single,
			&server.ShadowsocksRArgs{})
		if err := server.Start(); err != nil {
			return errors.Wrap(err, "add user error")
		}
	}
	s.userTable[user.Uid] = user
	// deal with all add users handles
	for _, handle := range s.addUserHandles {
		handle(user)
	}
	return nil
}

func (s *SSRManager) EditUser(user *model.UserInfo) error {
	logrus.Infof("edit user,uid: %v, port: %v", user.Uid, user.Port)
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	_, err := s.editUserReturn(user)
	return err
}

func (s *SSRManager) editUserReturn(user *model.UserInfo) (before *model.UserInfo, err error) {
	nodeInfo := core.GetApp().NodeInfo()
	// TODO after change user profile it will be simultaneously exist old port and new port
	before = s.userTable[user.Uid]
	if before == nil {
		return nil, errors.New(fmt.Sprintf("user %v dosen't exist", user.Uid))
	}
	if nodeInfo.Single != 1 && user.Port != before.Port && s.Shadowsocksrs[user.Port] != nil {
		return nil, errors.New(fmt.Sprintf("port %v used by user %v", user.Port, s.portToUidLocked(user.Port)))
	}
	if _, err := s.delUserReturl(user.Uid); err != nil {
		return nil, errors.Wrap(err, "edit user del user error")
	}
	if err := s.addUser(user); err != nil {
		return nil, errors.Wrap(err, "edit user add user error")
	}
	return before, nil
}

func (s *SSRManager) DelUser(uid int) error {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	logrus.Infof("del uid: %v \n", uid)
	_, err := s.delUserReturl(uid)
	return err
}

func (s *SSRManager) delUserReturl(uid int) (user *model.UserInfo, err error) {
	nodeInfo := core.GetApp().NodeInfo()
	port := s.uidToPortLocked(uid)

	if port == 0 {
		return nil, errors.New(fmt.Sprintf("uid %v is not esixt", uid))
	}

	if nodeInfo.Single == 1 {
		for _, server := range s.Shadowsocksrs {
			server.DelUser(port)
			logrus.Infof("server %v del %v success", server.Port, port)
		}
		user = s.userTable[uid]
		delete(s.userTable, uid)
	} else {
		server := s.Shadowsocksrs[port]
		if server == nil {
			logrus.WithFields(logrus.Fields{
				"port": port,
			}).Info("port is not exist")
			return nil, nil
		}

		if err := server.Close(); err != nil {
			return nil, err
		}
		user = s.userTable[uid]
		delete(s.Shadowsocksrs, port)
		delete(s.userTable, uid)
	}
	// deal with all add users handles
	for _, handle := range s.delUserHanelds {
		handle(uid)
	}
	return user, nil
}

func (s *SSRManager) GetUserFromPort(port int) *model.UserInfo {
	for _, value := range s.userTable {
		if value.Port == port {
			return value
		}
	}
	return nil
}

func (s *SSRManager) GetUserList() []*model.UserInfo {
	users := make([]*model.UserInfo, 0, len(s.userTable))
	for _, value := range s.userTable {
		users = append(users, value)
	}
	return users
}

func (s *SSRManager) RegisterAddUserHandle(handle AddUserHandle) {
	s.addUserHandles = append(s.addUserHandles, handle)
}

func (s *SSRManager) RegisterDelUserHandle(handle DelUserHandle) {
	s.delUserHanelds = append(s.delUserHanelds, handle)
}

//
//func (s *SSRManager) RestartWithNodeInfo(nodeInfo *model.NodeInfo) error {
//	users := s.GetUserList()
//
//	usersCopy := make([]*model.UserInfo, 0, len(users))
//	uids := make([]int, 0, len(users))
//
//	for _, user := range users {
//		uids = append(uids, user.Uid)
//		usersCopy = append(usersCopy, user)
//	}
//	err := s.DelUsers(uids)
//	if err != nil {
//		return err
//	}
//	err = s.AddUsers(usersCopy)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

func (s *SSRManager) ReportTask() {
	log.Info("ReportTask start")
	timer := time.Tick(1 * time.Second)
	tick := 0
	for {
		select {
		case <-s.Context.Done():
			log.Info("ReportTask close")
			return
		case <-timer:
		}
		if tick%60 == 0 {
			log.Info("trigger report task")
			traffic := s.ReportTraffic()
			log.Info("prepare report traffic data, data length: %v", len(traffic))
			if len(traffic) > 0 {
				if err := client.PostAllUserTraffic(traffic); err != nil {
					logrus.Error(err)
				}
			}
			online := s.ReportOnline()
			log.Info("prepare report online data, data length: %v", len(online))
			if len(online) > 0 {
				if err := client.PostNodeOnline(online); err != nil {
					logrus.Error(err)
				}
			}

			log.Info("post node status")
			if err := client.PostNodeStatus(s.ReportNodeStatus()); err != nil {
				logrus.Error(err)
			}
		}
		tick++
	}
}

func (s *SSRManager) GetUids() []int {
	uids := make([]int, 0, len(s.userTable))
	for key := range s.userTable {
		uids = append(uids, key)
	}
	return uids
}

func (s *SSRManager) Start() error {
	s.Lock()
	defer s.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	s.Context = ctx
	s.cancel = cancel
	nodeInfo := core.GetApp().NodeInfo()
	if nodeInfo.Single == 1 {
		portStrArray := strings.Split(nodeInfo.Port, ",")
		ports := []int{}
		for _, item := range portStrArray {
			convertPort, err := strconv.Atoi(item)
			if err != nil {
				panic(fmt.Sprintf("port format error: %s", nodeInfo.Port))
			}
			ports = append(ports, convertPort)
		}

		for _, port := range ports {
			s.NewShadowsocksRProxy(port,
				nodeInfo.Method,
				nodeInfo.Passwd,
				nodeInfo.Protocol,
				nodeInfo.ProtocolParam,
				nodeInfo.Obfs,
				nodeInfo.ObfsParam,
				nodeInfo.Single,
				&server.ShadowsocksRArgs{})
			err := s.Shadowsocksrs[port].Start()
			if err != nil {
				// TODO 错误处理
				return err
			}
		}
	}

	log.Info("prepare get user list")
	// load users
	users, err := client.GetUserList()
	if err != nil {
		logrus.Fatal(fmt.Sprintf("get user list error: %s,%s", err.Error(), string(debug.Stack())))
	}
	logrus.WithFields(logrus.Fields{
		"firstLoadUserCount": len(users),
	}).Info("get user list success")
	for i := 0; i < len(users); i++ {
		if err := s.AddUser(users[i]); err != nil {
			logrus.Error(err)
			return err
		}
	}
	go s.ReportTask()
	return nil
}

func (s *SSRManager) Close() error {
	s.Lock()
	defer s.Unlock()
	if s.cancel == nil {
		log.Error("service is not start. so it can't be close")
	}
	s.cancel()
	s.userTableLock.Lock()
	s.userTableLock.Unlock()
	if err := s.DelUsers(s.GetUids()); err != nil {
		return err
	}
	if core.GetApp().NodeInfo().Single == 1 {
		for _, value := range s.Shadowsocksrs {
			if err := value.Close(); err != nil {
				return err
			}
		}
		s.Shadowsocksrs = make(map[int]*server.ShadowsocksRProxy)
	}
	return nil
}

func (s *SSRManager) Reload() error {
	if err := s.Close(); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}
	return nil
}
