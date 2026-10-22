package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/core"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	obfspkg "github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/proxy/server"
	"github.com/ProxyPanel/VNet-SSR/utils/addrx"
	"github.com/ProxyPanel/VNet-SSR/utils/monitor"
	"github.com/ProxyPanel/VNet-SSR/utils/netx"
	"github.com/dustin/go-humanize"
	"github.com/sirupsen/logrus"
)

var (
	ssrManagerInstance = NewShadowsocksrService()
)

func GetSSRManager() *SSRManager {
	return ssrManagerInstance
}

type AddUserHandle func(*model.UserInfo)
type DelUserHandle func(*model.UserInfo)

// 流量上报的起报门槛与最长滞留：单行增量不足门槛时留在本地继续累加，
// 但滞留满 trafficReportMaxHold 就必须上报，不能让低流量账号的字节无限期停在节点上
const (
	trafficReportMinBytes = 50 * 1024
	trafficReportMaxHold  = 10 * time.Minute
)

func NewShadowsocksrService() *SSRManager {
	return &SSRManager{
		Locker:        new(sync.Mutex),
		Shadowsocksrs: make(map[int]*server.ShadowsocksRProxy),
		traffic:       make(map[int]*model.UserTraffic),
		trafficSince:  make(map[int]time.Time),
		trafficLock:   new(sync.Mutex),
		online:        make(map[int]*onlineEntry),
		onlineLock:    new(sync.Mutex),
		userTable:     make(map[int]*model.UserInfo),
		userTableLock: new(sync.Mutex),
		identityIndex: make(map[int]int),
		UpTime:        time.Now(),
		// 秒级时间戳会在同一秒内重启两次时复用批次号，面板按 (node, report_id) 认领一小时
		bootStamp: time.Now().UnixNano(),
	}
}

type SSRManager struct {
	sync.Locker
	// Shadowsocksrs 的读写横跨推送、重载与启动三条路径，必须有独立于 userTableLock 的锁
	Shadowsocksrs map[int]*server.ShadowsocksRProxy
	serversLock   sync.RWMutex
	traffic       map[int]*model.UserTraffic
	// trafficSince 记下「被门槛拦下的那批字节从何时开始攒」，用于最长滞留时间到点强制上报
	trafficSince  map[int]time.Time
	trafficLock   *sync.Mutex
	online        map[int]*onlineEntry
	onlineLock    *sync.Mutex
	userTable     map[int]*model.UserInfo
	userTableLock *sync.Mutex
	// identityIndex 是「线上身份编号 → uid」的 O(1) 反查表；身份编号两种模式下都是端口
	// （单端口下它不参与监听、只当账号编号用，auth 包头的 4 字节装的就是它；面板建号时已保证端口全局唯一）
	identityIndex map[int]int
	// usersGenMu 串行化「推送落地 / 周期对账 / 重载重建」三条改用户表的路径；
	// usersGen 在推送落地、周期同步与重载完成时递增，用来丢弃取数期间已经过期的快照
	usersGenMu     sync.Mutex
	usersGen       uint64
	UpTime         time.Time
	addUserHandles []AddUserHandle
	delUserHanelds []DelUserHandle
	context.Context
	cancel context.CancelFunc
	// reportDone 在 ReportTask 退出时关闭：重载与进程退出要等旧的一轮上报收口，
	// 否则两边可能同时 requeue 同一批
	reportDone chan struct{}
	// pendingTraffic 是上一次没送达的整批增量；面板按行上的 report_id 去重，所以整批原样重发、不再与新的合并
	pendingTraffic []*model.UserTraffic
	// pendingOnline 同 pendingTraffic：在线批次没送达就整批留到下一轮原样重发（report_id 不变），
	// 不再并回 s.online——并回会让集合排不空、把同一批人每分钟重复上报成新的在线行
	pendingOnline   []*model.NodeOnline
	bootStamp       int64
	reportSeq       uint64
	onlineReportSeq uint64
}

// IdentityToUid 按线上身份编号反查账号，查不到返回 0
func (s *SSRManager) IdentityToUid(identity int) int {
	s.userTableLock.Lock()
	uid := s.identityIndex[identity]
	s.userTableLock.Unlock()
	return uid
}

func (s *SSRManager) Upload(identity int, n int64) {
	s.addTraffic(identity, n, 0)
}

func (s *SSRManager) Download(identity int, n int64) {
	s.addTraffic(identity, 0, n)
}

func (s *SSRManager) addTraffic(identity int, up, down int64) {
	s.trafficLock.Lock()
	uid := s.IdentityToUid(identity)
	row := s.traffic[uid]
	if row == nil {
		row = &model.UserTraffic{Uid: uid}
		s.traffic[uid] = row
	}
	row.Upload += up
	row.Download += down
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
	for uid, value := range reportData {
		// uid 为 0 的是端口查不到账号的字节，面板不会收
		if value.Uid <= 0 {
			continue
		}
		since, held := s.trafficSince[uid]
		// 滞留到点的行必须走，哪怕还是不足门槛：不然掉线或被禁用的人剩下的尾巴永远不上账
		if value.Upload+value.Download < trafficReportMinBytes && (!held || time.Since(since) < trafficReportMaxHold) {
			s.retainTraffic(uid, value)
			continue
		}
		if held {
			delete(s.trafficSince, uid)
		}
		value.ReportID = reportID
		convertReportData = append(convertReportData, value)
	}

	return convertReportData
}

// retainTraffic 把没到门槛的增量并回本地表继续攒：这一分钟新到的字节可能已经先落进去了
func (s *SSRManager) retainTraffic(uid int, value *model.UserTraffic) {
	if _, seen := s.trafficSince[uid]; !seen {
		s.trafficSince[uid] = time.Now()
	}
	if cur := s.traffic[uid]; cur != nil {
		cur.Upload += value.Upload
		cur.Download += value.Download
		return
	}
	s.traffic[uid] = value
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

// 一个账号一分钟内最多上报的源 IP 数：面板只需要展示来源，不设上限时
// 单个用户可以用大量 IPv6 源地址把字符串撑到 TEXT 上限
const maxOnlineIPs = 16

type onlineEntry struct {
	ips map[string]struct{}
}

func (s *SSRManager) Online(identity int, ip string) {
	s.onlineLock.Lock()
	defer s.onlineLock.Unlock()
	uid := s.IdentityToUid(identity)
	if uid == 0 {
		log.Error("catch identity %v but uid is 0", identity)
		return
	}
	ip = addrx.SplitIpFromAddr(ip)
	if ip == "" {
		return
	}
	entry := s.online[uid]
	if entry == nil {
		entry = &onlineEntry{ips: make(map[string]struct{})}
		s.online[uid] = entry
	}
	if len(entry.ips) >= maxOnlineIPs {
		return
	}
	entry.ips[ip] = struct{}{}
}

// ReportOnline 取一批待上报的在线记录：上一批没送达就先原样重发那一批（report_id 不变，面板据此去重），
// 否则取走当前累计的快照并给它一个新 id。清空发生在发送之前，这一分钟的在线在面板侧只有一份记录
func (s *SSRManager) ReportOnline() []*model.NodeOnline {
	s.onlineLock.Lock()
	defer s.onlineLock.Unlock()

	if len(s.pendingOnline) > 0 {
		pending := s.pendingOnline
		s.pendingOnline = nil
		return pending
	}

	reportData := s.online
	s.online = make(map[int]*onlineEntry)

	s.onlineReportSeq++
	reportID := fmt.Sprintf("%d-%d-%d", core.GetApp().NodeId(), s.bootStamp, s.onlineReportSeq)

	convertReportData := make([]*model.NodeOnline, 0, len(reportData))
	for uid, entry := range reportData {
		ips := make([]string, 0, len(entry.ips))
		for ip := range entry.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		convertReportData = append(convertReportData, &model.NodeOnline{
			Uid:      uid,
			IP:       strings.Join(ips, ","),
			ReportID: reportID,
		})
	}

	return convertReportData
}

// requeueOnline 把没送达的整批留在原地等下一轮原样重发；并回 s.online 会让集合排不空、把同一批人反复上报成新的在线行
func (s *SSRManager) requeueOnline(data []*model.NodeOnline) {
	s.onlineLock.Lock()
	defer s.onlineLock.Unlock()

	if len(s.pendingOnline) > 0 {
		logrus.Errorf("pending online batch is not empty, drop %d rows", len(data))
		return
	}
	s.pendingOnline = data
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
	shadowsocksRProxy.OnlineReport = s
	shadowsocksRProxy.TrafficReport = s
	shadowsocksRProxy.Single = single
	shadowsocksRProxy.ILimiter = GetLimitInstance()
	shadowsocksRProxy.Users = obfspkg.NewUserTable()
	shadowsocksRProxy.HostFirewall = GetRuleService()
	if core.GetApp().NodeInfo().IsUDP == 1 {
		shadowsocksRProxy.UDPSwitch = "true"
	} else {
		shadowsocksRProxy.UDPSwitch = "false"
	}
	return shadowsocksRProxy
}

func (s *SSRManager) registerProxy(proxy *server.ShadowsocksRProxy) {
	s.serversLock.Lock()
	s.Shadowsocksrs[proxy.Port] = proxy
	s.serversLock.Unlock()
}

func (s *SSRManager) lookupProxy(port int) *server.ShadowsocksRProxy {
	s.serversLock.RLock()
	proxy := s.Shadowsocksrs[port]
	s.serversLock.RUnlock()
	return proxy
}

func (s *SSRManager) removeProxy(port int) *server.ShadowsocksRProxy {
	s.serversLock.Lock()
	proxy := s.Shadowsocksrs[port]
	delete(s.Shadowsocksrs, port)
	s.serversLock.Unlock()
	return proxy
}

func (s *SSRManager) snapshotProxies() []*server.ShadowsocksRProxy {
	s.serversLock.RLock()
	proxies := make([]*server.ShadowsocksRProxy, 0, len(s.Shadowsocksrs))
	for _, proxy := range s.Shadowsocksrs {
		proxies = append(proxies, proxy)
	}
	s.serversLock.RUnlock()
	return proxies
}

// 一次下发的来源，只用于日志：同样一批人可能来自推送、周期同步或启动全量，
// 事后看日志要能分辨是哪条路动的用户表
const (
	SourcePush   = "push"   // 面板推 /api/user/* 与 /api/v2/user/*
	SourcePoll   = "poll"   // 节点每 5 分钟的周期同步
	SourceBoot   = "boot"   // 启动时的全量落地
	SourceReload = "reload" // 重载时的全量落地
)

// applyAction 是一次下发对本地用户表的实际影响；applyNone 表示内容与本地一致，不值得记日志
type applyAction string

const (
	applyNone   applyAction = "none"
	applyAdd    applyAction = "add"
	applyEdit   applyAction = "edit"
	applyRemove applyAction = "remove"
)

// ApplyUsers 落下面发的目标状态：enable=0 摘掉账号，已存在且字段变了就换，完全一致则不动。
// 中途失败不回滚已应用的行——回滚等于把「更新过」的账号直接删掉，重投这批才是收敛路径。
func (s *SSRManager) ApplyUsers(source string, users []*model.UserInfo) error {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()

	var errs []string
	changed := 0

	for _, item := range users {
		action, err := s.applyUser(item)
		if err != nil {
			errs = append(errs, fmt.Sprintf("uid %v: %s", item.Uid, err.Error()))

			continue
		}

		// 只有真的动了表才记一行：全量下发里没变的账号占了绝大多数，逐行记就成了噪音
		if action != applyNone {
			changed++
			logrus.Infof("apply user %v, uid: %v, port: %v, source: %v", action, item.Uid, item.Port, source)
		}
	}

	// 整批没有一个账号落地成变动时留一行：否则这一轮全量下发在日志里是空的，
	// 看日志的人分不清「面板没人改动」还是「改动没送到」
	if changed == 0 && len(errs) == 0 && len(users) > 0 {
		log.Info("apply users no change, source: %v, total: %v", source, len(users))
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// planApply 只判「这条下发相对本地表要做什么」，不碰监听器：enable=0 是摘号，表里没行是建号，
// 内容一致什么都不动，其余是换号
func planApply(before, target *model.UserInfo) applyAction {
	if target.Enable == 0 {
		if before == nil { // 本来就不在表里，与「已摘掉」同义
			return applyNone
		}

		return applyRemove
	}

	if before == nil {
		return applyAdd
	}
	if *before == *target {
		return applyNone
	}

	return applyEdit
}

// applyUser 调用方需持有 userTableLock
func (s *SSRManager) applyUser(user *model.UserInfo) (applyAction, error) {
	if user.Uid <= 0 {
		return applyNone, errors.New("uid must be positive")
	}

	action := planApply(s.userTable[user.Uid], user)

	// 缺 port/passwd 的行不能落：port 0 会真的去绑一个随机端口（多端口）或让线上认不出人（单端口），空密码等于开放账号
	if action == applyAdd || action == applyEdit {
		if user.Port <= 0 || user.Port > 65535 {
			return applyNone, errors.New(fmt.Sprintf("uid %v has invalid port %v", user.Uid, user.Port))
		}
		if user.Passwd == "" {
			return applyNone, errors.New(fmt.Sprintf("uid %v has empty passwd", user.Uid))
		}
	}

	switch action {
	case applyRemove:
		if _, err := s.delUserReturl(user.Uid); err != nil {
			return applyNone, err
		}
	case applyAdd:
		if err := s.addUser(user); err != nil {
			return applyNone, err
		}
	case applyEdit:
		if _, err := s.editUserReturn(user); err != nil {
			return applyNone, err
		}
	}

	return action, nil
}

// ErrStaleUserSnapshot 表示周期同步取数期间已有推送落地，这份快照不能再应用
var ErrStaleUserSnapshot = errors.New("stale user snapshot")

// UsersGeneration 在取全量用户表之前取一次，落地时用它判断期间有没有推送
func (s *SSRManager) UsersGeneration() uint64 {
	s.usersGenMu.Lock()
	defer s.usersGenMu.Unlock()
	return s.usersGen
}

// ApplyUsersFromPush 把推送落地与代次递增放在同一把锁里：周期同步要么看到推送前的旧代次
// 并丢弃快照，要么在推送之后整批落地，不会把新密码/新账号覆盖回旧值
func (s *SSRManager) ApplyUsersFromPush(users []*model.UserInfo) error {
	s.usersGenMu.Lock()
	defer s.usersGenMu.Unlock()

	err := s.ApplyUsers(SourcePush, users)
	// 即使有行失败，已经应用的行也改变了本地表，周期同步必须丢弃旧快照重新取数
	s.usersGen++
	return err
}

func (s *SSRManager) DelUserFromPush(uid int) error {
	s.usersGenMu.Lock()
	defer s.usersGenMu.Unlock()
	err := s.DelUser(uid)
	s.usersGen++
	return err
}

func (s *SSRManager) DelUsersFromPush(uids []int) error {
	s.usersGenMu.Lock()
	defer s.usersGenMu.Unlock()
	err := s.DelUsers(uids)
	s.usersGen++
	return err
}

// SyncUsers 用面板的全量集合收敛本地表：userList 只含有效账号，缺席即视为该摘掉
func (s *SSRManager) SyncUsers(users []*model.UserInfo) error {
	s.usersGenMu.Lock()
	defer s.usersGenMu.Unlock()
	return s.syncUsersLocked(users)
}

// SyncUsersIfUnchanged 只在取数之后没有推送落地时应用快照
func (s *SSRManager) SyncUsersIfUnchanged(users []*model.UserInfo, gen uint64) error {
	s.usersGenMu.Lock()
	defer s.usersGenMu.Unlock()
	if gen != s.usersGen {
		return ErrStaleUserSnapshot
	}
	return s.syncUsersLocked(users)
}

func (s *SSRManager) syncUsersLocked(users []*model.UserInfo) error {
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

	var errs []string
	for _, uid := range stale {
		if err := s.DelUser(uid); err != nil {
			errs = append(errs, fmt.Sprintf("sync del user %v: %s", uid, err.Error()))
		}
	}

	if err := s.ApplyUsers(SourcePoll, users); err != nil {
		errs = append(errs, err.Error())
	}
	// 同步落地也推进代次：取数期间跑了同步的重载快照同样已经过期，不能让它把结果覆盖回去
	s.usersGen++
	if len(errs) > 0 {
		// 调用方据此作废 ETag；只在日志里留一行的话，下一次 304 会让这行失败永远没有重试机会
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *SSRManager) DelUsers(uids []int) error {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	users := make([]*model.UserInfo, 0, len(uids))
	for _, uid := range uids {
		// 已不存在的 uid 按目标状态已达成处理：丢失响应后的重投不能再把整批判失败
		if s.userTable[uid] == nil {
			continue
		}
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
		logrus.Infof("del uid: %v, port: %v", item.Uid, item.Port)
	}
	return nil
}

func (s *SSRManager) addUser(user *model.UserInfo) error {
	nodeInfo := core.GetApp().NodeInfo()
	if user2 := s.userTable[user.Uid]; user2 != nil {
		return errors.New(fmt.Sprintf("user %v already exist", user2.Uid))
	}
	identity := user.Port
	if nodeInfo.Single == 1 {
		for _, proxy := range s.snapshotProxies() {
			proxy.AddUser(identity, user.Passwd)
		}
	} else {
		if s.lookupProxy(user.Port) != nil {
			// 调用方已持有 userTableLock，直读索引而不是走加锁的 IdentityToUid
			return errors.New(fmt.Sprintf("add user port %v is used by %v", user.Port, s.identityIndex[user.Port]))
		}
		proxy := s.NewShadowsocksRProxy(
			user.Port,
			nodeInfo.Method,
			user.Passwd,
			nodeInfo.Protocol,
			nodeInfo.ProtocolParam,
			nodeInfo.Obfs,
			nodeInfo.ObfsParam,
			nodeInfo.Single,
			&server.ShadowsocksRArgs{})
		if err := proxy.Start(); err != nil {
			// Start 可能只起来了 TCP 或 UDP 的一半，先关掉；不能把没有用户的条目留在表里，
			// 否则后续重试会一直撞「端口已占用」
			_ = proxy.Close()
			return fmt.Errorf("%s: %w", "add user error", err)
		}
		s.registerProxy(proxy)
	}
	s.userTable[user.Uid] = user
	s.identityIndex[identity] = user.Uid
	// deal with all add users handles
	for _, handle := range s.addUserHandles {
		handle(user)
	}
	return nil
}

func (s *SSRManager) editUserReturn(user *model.UserInfo) (before *model.UserInfo, err error) {
	nodeInfo := core.GetApp().NodeInfo()
	// 换端口先摘旧监听再建新监听，两个端口不会同时存在
	before = s.userTable[user.Uid]
	if before == nil {
		return nil, errors.New(fmt.Sprintf("user %v dosen't exist", user.Uid))
	}
	if nodeInfo.Single != 1 && user.Port != before.Port && s.lookupProxy(user.Port) != nil {
		return nil, errors.New(fmt.Sprintf("port %v used by user %v", user.Port, s.identityIndex[user.Port]))
	}
	if _, err := s.delUserReturl(user.Uid); err != nil {
		return nil, fmt.Errorf("%s: %w", "edit user del user error", err)
	}
	if err := s.addUser(user); err != nil {
		return nil, fmt.Errorf("%s: %w", "edit user add user error", err)
	}
	return before, nil
}

func (s *SSRManager) DelUser(uid int) error {
	s.userTableLock.Lock()
	defer s.userTableLock.Unlock()
	// 已不存在的 uid 视为已达成目标：重投删除不能因为「本来就不在」而失败
	if s.userTable[uid] == nil {
		return nil
	}
	user, err := s.delUserReturl(uid)
	if err != nil {
		return err
	}
	logrus.Infof("del uid: %v, port: %v", user.Uid, user.Port)
	return nil
}

func (s *SSRManager) delUserReturl(uid int) (user *model.UserInfo, err error) {
	nodeInfo := core.GetApp().NodeInfo()
	user = s.userTable[uid]

	if user == nil {
		return nil, errors.New(fmt.Sprintf("uid %v is not esixt", uid))
	}

	identity := user.Port

	if nodeInfo.Single == 1 {
		for _, proxy := range s.snapshotProxies() {
			proxy.DelUser(identity)
			logrus.Infof("server %v del %v success", proxy.Port, identity)
		}
		delete(s.identityIndex, identity)
		delete(s.userTable, uid)
	} else {
		proxy := s.lookupProxy(identity)

		if proxy == nil {
			logrus.WithFields(logrus.Fields{
				"port": identity,
			}).Info("port is not exist")
			// 表里有行但端口上没有进程，是上一次添加失败留下的残行；留着会让禁用和删除都清不干净
			delete(s.identityIndex, identity)
			delete(s.userTable, uid)

			return user, nil
		}

		if err := proxy.Close(); err != nil {
			return nil, err
		}
		s.removeProxy(identity)
		delete(s.identityIndex, identity)
		delete(s.userTable, uid)
	}
	// deal with all add users handles
	for _, handle := range s.delUserHanelds {
		handle(user)
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

// ReportTask 用启动时传入的 ctx 退出：Restart 会替换 s.Context，协程里再读那个字段就盯不到自己的 cancel
func (s *SSRManager) ReportTask(ctx context.Context) {
	log.Info("ReportTask start")
	timer := time.NewTicker(1 * time.Second)
	defer timer.Stop()
	tick := 0
	for {
		select {
		case <-ctx.Done():
			log.Info("ReportTask close")
			return
		case <-timer.C:
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
			// 取数期间落地的推送会让这份快照立刻过期，落地前按代次再判一次
			gen := s.UsersGeneration()
			users, unchanged, err := client.SyncUserList()
			if err != nil {
				logrus.Error(err)
			} else if !unchanged {
				if err := s.SyncUsersIfUnchanged(users, gen); err != nil {
					if errors.Is(err, ErrStaleUserSnapshot) {
						log.Info("discard stale user snapshot: push landed during fetch")
					} else {
						logrus.Error(err)
					}
					// 快照已作废或没有完整落地：作废 ETag，下一轮重新取全量
					client.MarkUserListStale()
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
		return fmt.Errorf("%s: %w", "get user list error", err)
	}

	return s.startWith(users, SourceBoot)
}

// startWith 按给定的全量集合重建服务：集合要在 Close 之前取好，取不到时当前服务原样保留
func (s *SSRManager) startWith(users []*model.UserInfo, source string) error {
	s.Lock()
	defer s.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	s.Context = ctx
	s.cancel = cancel
	nodeInfo := core.GetApp().NodeInfo()
	if nodeInfo.Single == 1 {
		ports, err := parseSinglePorts(nodeInfo.Port)
		if err != nil {
			cancel()
			return err
		}
		started := make([]*server.ShadowsocksRProxy, 0, len(ports))
		for _, port := range ports {
			proxy := s.NewShadowsocksRProxy(port,
				nodeInfo.Method,
				nodeInfo.Passwd,
				nodeInfo.Protocol,
				nodeInfo.ProtocolParam,
				nodeInfo.Obfs,
				nodeInfo.ObfsParam,
				nodeInfo.Single,
				&server.ShadowsocksRArgs{})
			if err := proxy.Start(); err != nil {
				_ = proxy.Close()
				for _, opened := range started {
					s.removeProxy(opened.Port)
					_ = opened.Close()
				}
				cancel()
				return err
			}
			s.registerProxy(proxy)
			started = append(started, proxy)
		}
	}

	logrus.WithFields(logrus.Fields{
		"firstLoadUserCount": len(users),
	}).Info("get user list success")
	// 单个端口冲突（两人同端口）不该挡住其余账号，其余人这轮已经生效
	if err := s.ApplyUsers(source, users); err != nil {
		logrus.Error(err)
	}
	done := make(chan struct{})
	s.reportDone = done
	go func() {
		defer close(done)
		s.ReportTask(ctx)
	}()
	return nil
}

// parseSinglePorts 解析单端口的 port 列表；格式错误要在关监听之前拒绝，不能靠 panic 带掉整节点
func parseSinglePorts(raw string) ([]int, error) {
	items := strings.Split(raw, ",")
	ports := make([]int, 0, len(items))
	for _, item := range items {
		port, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("port format error: %q", raw)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// stopReportLoop 取消上报协程并等它退出：旧任务还在一轮上报里时启动新任务，
// 两边会同时 requeue 同一批，pending 只能留一份，另一份会被丢掉
func (s *SSRManager) stopReportLoop(wait time.Duration) {
	s.Lock()
	cancel, done := s.cancel, s.reportDone
	s.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(wait):
		log.Error("ReportTask did not stop within %s", wait)
	}
}

func (s *SSRManager) Close() error {
	s.stopReportLoop(10 * time.Second)
	s.Lock()
	defer s.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	} else {
		log.Error("service is not start. so it can't be close")
	}
	s.reportDone = nil
	delErr := s.DelUsers(s.GetUids())

	// 无论单端口还是多端口，最后都把端口索引清空：DelUsers 中途失败时也不能留下半关的监听器
	proxies := s.snapshotProxies()
	s.serversLock.Lock()
	s.Shadowsocksrs = make(map[int]*server.ShadowsocksRProxy)
	s.serversLock.Unlock()

	var closeErr error
	for _, proxy := range proxies {
		if err := proxy.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	if delErr != nil {
		return delErr
	}
	return closeErr
}

// Restart 用调用方取好的全量集合重建服务；集合必须在 Close 之前取，取不到时当前服务原样保留。
// gen 是取数前记下的代次：取数期间落地的推送/同步已经改过内存表，重建必须用那份新状态
func (s *SSRManager) Restart(users []*model.UserInfo, gen uint64) error {
	// 先停旧上报协程再拿 usersGenMu：一轮同步可能正卡在这把锁上，握着锁等它退出会互相等
	s.stopReportLoop(10 * time.Second)

	s.usersGenMu.Lock()
	defer s.usersGenMu.Unlock()
	if gen != s.usersGen {
		log.Info("user table changed during reload fetch, rebuilding from live table")
		users = s.GetUserList()
	}
	if err := s.Close(); err != nil {
		return err
	}
	if err := s.startWith(users, SourceReload); err != nil {
		return err
	}
	s.usersGen++
	return nil
}

// Shutdown 在进程退出前把当前与待发的流量/在线批次再投一次；失败只剩日志，
// 进程退出后内存里的账本来就会消失
func (s *SSRManager) Shutdown() {
	s.stopReportLoop(15 * time.Second)

	s.usersGenMu.Lock()
	defer s.usersGenMu.Unlock()
	s.flushReports()
	if err := s.Close(); err != nil {
		logrus.Error(err)
	}
}

func (s *SSRManager) flushReports() {
	for i := 0; i < 2; i++ {
		batch := s.ReportTraffic()
		if len(batch) == 0 {
			break
		}
		if err := client.PostAllUserTraffic(batch); err != nil {
			logrus.Error(err)
			s.requeueTraffic(batch)
			break
		}
	}
	for i := 0; i < 2; i++ {
		batch := s.ReportOnline()
		if len(batch) == 0 {
			break
		}
		if err := client.PostNodeOnline(batch); err != nil {
			logrus.Error(err)
			s.requeueOnline(batch)
			break
		}
	}
}
