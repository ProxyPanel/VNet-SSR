package service

import (
	"context"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/core"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProxyPanel/VNet-SSR/common/network"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/proxy/server"
	"github.com/ProxyPanel/VNet-SSR/utils/addrx"
	"github.com/ProxyPanel/VNet-SSR/utils/monitor"
	"github.com/ProxyPanel/VNet-SSR/utils/netx"
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
		bootStamp:     time.Now().Unix(),
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
	// pendingTraffic 是上一次没送达的整批增量；面板按行上的 report_id 去重，所以整批原样重发、不再与新的合并
	pendingTraffic []*model.UserTraffic
	bootStamp      int64
	reportSeq      uint64
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

// ReportTraffic 取一批待上报的增量：上一批没送达就先原样重发那一批（report_id 不变，面板据此去重），
// 否则取走当前累计的快照并给它一个新 id。清账发生在发送之前，这一分钟的字节在面板侧只有一份记录
func (s *SSRManager) ReportTraffic() []*model.UserTraffic {
	s.trafficLock.Lock()
	defer s.trafficLock.Unlock()

	if len(s.pendingTraffic) > 0 {
		pending := s.pendingTraffic
		s.pendingTraffic = nil
		return pending
	}

	reportData := s.traffic
	s.traffic = make(map[int]*model.UserTraffic)

	s.reportSeq++
	reportID := fmt.Sprintf("%d-%d-%d", core.GetApp().NodeId(), s.bootStamp, s.reportSeq)

	convertReportData := make([]*model.UserTraffic, 0, len(reportData))
	for _, value := range reportData {
		// uid 为 0 的是端口查不到账号的字节，面板不会收
		if value.Uid <= 0 {
			continue
		}
		value.ReportID = reportID
		convertReportData = append(convertReportData, value)
	}

	return convertReportData
}

// requeueTraffic 把没送达的整批留在原地等下一轮重发；与新的增量合并会让 report_id 对不上内容，去重就废了
func (s *SSRManager) requeueTraffic(data []*model.UserTraffic) {
	s.trafficLock.Lock()
	defer s.trafficLock.Unlock()

	if len(s.pendingTraffic) > 0 {
		// 理论上到不了这里：一批只会在上一批送出结果之后才取下一批
		logrus.Errorf("pending traffic batch is not empty, drop %d rows", len(data))
		return
	}
	s.pendingTraffic = data
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
	defer s.onlineLock.Unlock()

	reportData := s.online
	convertReportData := make([]*model.NodeOnline, 0, len(reportData))
	for _, value := range reportData {
		convertReportData = append(convertReportData, value)
	}
	s.online = make(map[int]*model.NodeOnline)

	return convertReportData
}

// requeueOnline 把没送达的在线记录并回待上报表，IP 去重沿用 Online() 的拼接判据
func (s *SSRManager) requeueOnline(data []*model.NodeOnline) {
	s.onlineLock.Lock()
	defer s.onlineLock.Unlock()

	for _, value := range data {
		current := s.online[value.Uid]
		if current == nil {
			current = &model.NodeOnline{Uid: value.Uid}
			s.online[value.Uid] = current
		}

		for _, ip := range strings.Split(value.IP, ",") {
			if ip == "" || strings.Contains(current.IP, ip) {
				continue
			}

			if current.IP == "" {
				current.IP = ip
			} else {
				current.IP = current.IP + "," + ip
			}
		}
	}
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

// ApplyUsers 落下面发的目标状态：enable=0 摘掉账号，已存在且字段变了就换，完全一致则不动。
// 中途失败不回滚已应用的行——回滚等于把「更新过」的账号直接删掉，重投这批才是收敛路径。
func (s *SSRManager) ApplyUsers(users []*model.UserInfo) error {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()

	var errs []string

	for _, item := range users {
		if err := s.applyUser(item); err != nil {
			errs = append(errs, fmt.Sprintf("uid %v: %s", item.Uid, err.Error()))

			continue
		}

		logrus.Infof("apply user,uid: %v, port: %v", item.Uid, item.Port)
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// applyUser 调用方需持有 userTableLock
func (s *SSRManager) applyUser(user *model.UserInfo) error {
	if user.Uid <= 0 {
		return errors.New("uid must be positive")
	}

	if user.Enable == 0 {
		// 本来就不在节点上时 delUserReturl 会报错，这里与「已摘掉」同义
		_, _ = s.delUserReturl(user.Uid)

		return nil
	}

	// 缺 port/passwd 的行不能落：port 0 会真的去绑一个随机端口，空密码等于开放账号
	if user.Port <= 0 || user.Port > 65535 {
		return errors.New(fmt.Sprintf("uid %v has invalid port %v", user.Uid, user.Port))
	}
	if user.Passwd == "" {
		return errors.New(fmt.Sprintf("uid %v has empty passwd", user.Uid))
	}

	before := s.userTable[user.Uid]
	if before == nil {
		return s.addUser(user)
	}
	if *before == *user {
		return nil
	}

	_, err := s.editUserReturn(user)

	return err
}

// SyncUsers 用面板的全量集合收敛本地表：userList 只含有效账号，缺席即视为该摘掉
func (s *SSRManager) SyncUsers(users []*model.UserInfo) error {
	s.userTableLock.Lock()

	keep := make(map[int]bool, len(users))
	for _, item := range users {
		keep[item.Uid] = true
	}

	var stale []int

	for uid := range s.userTable {
		if !keep[uid] {
			stale = append(stale, uid)
		}
	}

	s.userTableLock.Unlock()

	for _, uid := range stale {
		if err := s.DelUser(uid); err != nil {
			logrus.Errorf("sync del user,uid: %v, error: %s", uid, err.Error())
		}
	}

	return s.ApplyUsers(users)
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

func (s *SSRManager) AddUser(user *model.UserInfo) error {
	logrus.Infof("add user,uid: %v, port: %v", user.Uid, user.Port)
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	return s.applyUser(user)
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
	return s.applyUser(user)
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
		user = s.userTable[uid]

		if server == nil {
			logrus.WithFields(logrus.Fields{
				"port": port,
			}).Info("port is not exist")
			// 表里有行但端口上没有进程，是上一次添加失败留下的残行；留着会让禁用和删除都清不干净
			delete(s.userTable, uid)

			return user, nil
		}

		if err := server.Close(); err != nil {
			return nil, err
		}
		delete(s.Shadowsocksrs, port)
		delete(s.userTable, uid)
	}
	// deal with all add users handles
	for _, handle := range s.delUserHanelds {
		handle(uid)
	}
	return user, nil
}

func (s *SSRManager) GetUserList() []*model.UserInfo {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
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

// ReportTask 用启动时传入的 ctx 退出：Restart 会替换 s.Context，协程里再读那个字段就盯不到自己的 cancel
func (s *SSRManager) ReportTask(ctx context.Context) {
	log.Info("ReportTask start")
	timer := time.Tick(1 * time.Second)
	tick := 0
	for {
		select {
		case <-ctx.Done():
			log.Info("ReportTask close")
			return
		case <-timer:
		}
		if tick%60 == 0 {
			log.Info("trigger report task")
			// 转发收口按分钟聚合：日志量与时间成正比，而不是与连接数成正比
			if summary := netx.CopyEndSummary(); summary != "" {
				log.Info("copy ended last minute: %s", summary)
			}
			traffic := s.ReportTraffic()
			log.Info("prepare report traffic data, data length: %v", len(traffic))
			if len(traffic) > 0 {
				if err := client.PostAllUserTraffic(traffic); err != nil {
					logrus.Error(err)
					// 快照已经清账，没送达的必须并回去，否则这一分钟的字节永久消失
					s.requeueTraffic(traffic)
				}
			}
			online := s.ReportOnline()
			log.Info("prepare report online data, data length: %v", len(online))
			if len(online) > 0 {
				if err := client.PostNodeOnline(online); err != nil {
					logrus.Error(err)
					s.requeueOnline(online)
				}
			}

			log.Info("post node status")
			if err := client.PostNodeStatus(s.ReportNodeStatus()); err != nil {
				logrus.Error(err)
			}
		}
		// 推送只是加速器：每 5 分钟按 If-None-Match 问一次全量集合，丢掉的推送最迟 5 分钟补上
		if tick > 0 && tick%300 == 0 {
			users, unchanged, err := client.SyncUserList()
			if err != nil {
				logrus.Error(err)
			} else if !unchanged {
				if err := s.SyncUsers(users); err != nil {
					logrus.Error(err)
				}
			}
		}
		tick++
	}
}

func (s *SSRManager) GetUids() []int {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	uids := make([]int, 0, len(s.userTable))
	for key := range s.userTable {
		uids = append(uids, key)
	}
	return uids
}

func (s *SSRManager) Start() error {
	log.Info("prepare get user list")
	// load users
	users, err := client.GetUserList()
	if err != nil {
		return errors.Wrap(err, "get user list error")
	}

	return s.startWith(users)
}

// startWith 按给定的全量集合重建服务：集合要在 Close 之前取好，取不到时当前服务原样保留
func (s *SSRManager) startWith(users []*model.UserInfo) error {
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
				return err
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"firstLoadUserCount": len(users),
	}).Info("get user list success")
	// 单个端口冲突（两人同端口）不该挡住其余账号，其余人这轮已经生效
	if err := s.ApplyUsers(users); err != nil {
		logrus.Error(err)
	}
	go s.ReportTask(ctx)
	return nil
}

func (s *SSRManager) Close() error {
	s.Lock()
	defer s.Unlock()
	if s.cancel == nil {
		log.Error("service is not start. so it can't be close")
	}
	s.cancel()
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

// Restart 用调用方取好的全量集合重建服务；集合必须在 Close 之前取，取不到时当前服务原样保留
func (s *SSRManager) Restart(users []*model.UserInfo) error {
	if err := s.Close(); err != nil {
		return err
	}
	return s.startWith(users)
}
