package service

import (
	"context"
	"sync"
	"time"

	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	limitInstance = NewLimit()
)

func GetLimitInstance() *Limit {
	return limitInstance
}

func init() {
	GetSSRManager().RegisterAddUserHandle(func(userInfo *model.UserInfo) {
		identity := userInfo.Port
		// prefer use node limit when node limit less then user limit
		if core.GetApp().NodeInfo().SpeedLimit == 0 ||
			(core.GetApp().NodeInfo().SpeedLimit > userInfo.Limit && userInfo.Limit != 0) {
			limitInstance.Set(identity, int(userInfo.Limit))
		} else {
			limitInstance.Set(identity, int(core.GetApp().NodeInfo().SpeedLimit))
		}
	})

	GetSSRManager().RegisterDelUserHandle(func(userInfo *model.UserInfo) {
		// 与 Set 同一个键：会话侧 UpLimit/DownLimit 也是按身份编号取的限速器
		limitInstance.Del(userInfo.Port)
	})
}

type Limit struct {
	gLocker    sync.RWMutex
	upLimits   map[int]*rate.Limiter
	downLimits map[int]*rate.Limiter
}

func NewLimit() *Limit {
	return &Limit{
		upLimits:   make(map[int]*rate.Limiter),
		downLimits: make(map[int]*rate.Limiter),
	}
}

// Set/Del 的键是线上身份编号（两种模式下都是端口），与会话侧 UpLimit/DownLimit 传的同一个值
func (l *Limit) Set(identity int, limit int) {
	l.gLocker.Lock()
	defer l.gLocker.Unlock()

	if limit <= 0 {
		logrus.Infof("limit remove %v, because limit is zero", identity)
		delete(l.upLimits, identity)
		delete(l.downLimits, identity)
		return
	}
	logrus.Infof("limit add %v:%v", identity, limit)
	l.upLimits[identity] = rate.NewLimiter(rate.Limit(limit), limit)
	l.downLimits[identity] = rate.NewLimiter(rate.Limit(limit), limit)
}

func (l *Limit) Del(identity int) {
	l.gLocker.Lock()
	defer l.gLocker.Unlock()
	logrus.Infof("limit remove %v", identity)
	delete(l.upLimits, identity)
	delete(l.downLimits, identity)
}

func (l *Limit) UpLimit(identity, n int) error {
	return waitN(l.lookup(l.upLimits, identity), n)
}

func (l *Limit) DownLimit(identity, n int) error {
	return waitN(l.lookup(l.downLimits, identity), n)
}

// AllowUp/AllowDown 是 UDP 的非阻塞判据：UDP 只有一个读协程，阻塞在这里会把整端口的
// 其他客户端一起卡住，超额时丢这一包即可
func (l *Limit) AllowUp(identity, n int) bool {
	return allowN(l.lookup(l.upLimits, identity), n)
}

func (l *Limit) AllowDown(identity, n int) bool {
	return allowN(l.lookup(l.downLimits, identity), n)
}

func (l *Limit) lookup(limits map[int]*rate.Limiter, identity int) *rate.Limiter {
	l.gLocker.RLock()
	limiter := limits[identity]
	l.gLocker.RUnlock()
	return limiter
}

// waitN 把超过桶容量的长度拆成多次 WaitN：单个 TCP 读最多 4KiB，
// 而限速阈值可以是 1B/s，一次 WaitN(4096) 会因超过 burst 直接报错并失去限速
func waitN(limiter *rate.Limiter, n int) error {
	if limiter == nil || n <= 0 {
		return nil
	}
	for n > 0 {
		chunk := n
		if burst := limiter.Burst(); chunk > burst {
			chunk = burst
		}
		if err := limiter.WaitN(context.Background(), chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

func allowN(limiter *rate.Limiter, n int) bool {
	if limiter == nil || n <= 0 {
		return true
	}
	// 单个数据报大于桶容量时不能按「超额」丢掉：低阈值下所有大包都会被丢，等于反方向的限速失效
	if n > limiter.Burst() {
		return true
	}
	return limiter.AllowN(time.Now(), n)
}
