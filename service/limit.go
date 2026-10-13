package service

import (
	"context"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"sync"
)

var (
	limitInstance = NewLimit()
)

func GetLimitInstance() *Limit {
	return limitInstance;
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
	gLocker    sync.Locker
	upLimits   map[int]*rate.Limiter
	downLimits map[int]*rate.Limiter
}

func NewLimit() *Limit {
	return &Limit{
		gLocker:    new(sync.Mutex),
		upLimits:   make(map[int]*rate.Limiter),
		downLimits: make(map[int]*rate.Limiter),
	}
}

// Set/Del 的键是线上身份编号（两种模式下都是端口），与会话侧 UpLimit/DownLimit 传的同一个值
func (l *Limit) Set(identity int, limit int) {
	l.gLocker.Lock()
	defer l.gLocker.Unlock()

	if limit != 0 {
		logrus.Infof("limit add %v:%v", identity, limit)
		l.upLimits[identity] = rate.NewLimiter(rate.Limit(limit), limit)
		l.downLimits[identity] = rate.NewLimiter(rate.Limit(limit), limit)
	} else {
		logrus.Infof("limit ignore zero limit identity: %v", identity)
	}

}

func (l *Limit) Del(identity int) {
	l.gLocker.Lock()
	defer l.gLocker.Unlock()
	logrus.Infof("limit remove %v", identity)
	delete(l.upLimits, identity)
	delete(l.downLimits, identity)
}

func (l *Limit) UpLimit(identity, n int) error {
	if l.upLimits[identity] != nil {
		return l.upLimits[identity].WaitN(context.Background(), n)
	}
	return nil
}

func (l *Limit) DownLimit(identity, n int) error {
	if l.downLimits[identity] != nil {
		return l.downLimits[identity].WaitN(context.Background(), n)
	}
	return nil
}

func (l *Limit) Wait(identity, n int) error {
	if l.upLimits[identity] != nil {
		return l.upLimits[identity].WaitN(context.Background(), n)
	}
	return nil
}
