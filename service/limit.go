package service

import (
	"context"
	"github.com/rc452860/vnet/core"
	"github.com/rc452860/vnet/model"
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
		// prefer use node limit when node limit less then user limit
		if core.GetApp().NodeInfo().SpeedLimit == 0 ||
			(core.GetApp().NodeInfo().SpeedLimit > userInfo.Limit && userInfo.Limit != 0) {
			limitInstance.Set(userInfo.Port, int(userInfo.Limit))
		} else {
			limitInstance.Set(userInfo.Port, int(core.GetApp().NodeInfo().SpeedLimit))
		}
	})

	GetSSRManager().RegisterDelUserHandle(func(uid int) {
		limitInstance.Del(uid)
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

func (l *Limit) Set(uid int, limition int) {
	l.gLocker.Lock()
	defer l.gLocker.Unlock()

	if limition != 0 {
		logrus.Infof("limit add %v:%v", uid, limition)
		l.upLimits[uid] = rate.NewLimiter(rate.Limit(limition), int(limition))
		l.downLimits[uid] = rate.NewLimiter(rate.Limit(limition), int(limition))
	} else {
		logrus.Infof("limit ignore zero limit uid: %v", uid)
	}

}

func (l *Limit) Del(uid int) {
	l.gLocker.Lock()
	defer l.gLocker.Unlock()
	logrus.Infof("limit remove %v", uid)
	delete(l.upLimits, uid)
}

func (l *Limit) UpLimit(uid, n int) error {
	if l.upLimits[uid] != nil {
		return l.upLimits[uid].WaitN(context.Background(), n)
	}
	return nil
}

func (l *Limit) DownLimit(uid, n int) error {
	if l.downLimits[uid] != nil {
		return l.downLimits[uid].WaitN(context.Background(), n)
	}
	return nil
}

func (l *Limit) Wait(uid, n int) error {
	if l.upLimits[uid] != nil {
		return l.upLimits[uid].WaitN(context.Background(), n)
	}
	return nil
}
